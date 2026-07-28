"""QR Code Generator: gera um QR code local (sem chamada de rede) a partir de
texto ou URL arbitrários, num dos tamanhos pré-configurados.

`is_publicly_indexable = False` de propósito: a entrada é texto livre do
usuário (pode ser um Wi-Fi, um link privado, um número de telefone...), então
essa ferramenta nunca deve gerar página estática pública nem aparecer em
nenhuma listagem de "consultas recentes" — `SearchService.submit` já deriva
`visibility=PRIVATE` a partir dessa mesma flag.
"""
from __future__ import annotations

import base64
import io

import qrcode
from PIL import Image

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError

ALLOWED_SIZES = [150, 200, 300, 400, 500, 800, 1000]
_DEFAULT_SIZE = 300
_MAX_TEXT_LENGTH = 1500


class QrCodeGeneratorTool(BaseTool):
    slug = "qr-code-generator"
    name = "QR Code Generator"
    category_slug = "utils"
    short_description = "Generate a QR code from any text or URL, in a few preset pixel sizes."
    description = "Creates a downloadable QR code image from text or a URL, at a size you choose."
    icon = "qr-code"
    input_type = InputType.TEXT
    input_placeholder = "https://example.com or any text"
    public_url_prefix = "utils/qr-code"
    ttl_seconds = 3600
    rate_limit_per_minute = 20
    is_publicly_indexable = False
    analyzer_version = 1

    secondary_input_field = "qr_size"

    def validate_input(self, raw_input: str) -> str:
        size_part, _, text_part = raw_input.partition("::")
        text = text_part.strip()
        if not text:
            raise ToolValidationError("Please enter some text or a URL to encode.")
        if len(text) > _MAX_TEXT_LENGTH:
            raise ToolValidationError(f"Text is too long for a QR code (max {_MAX_TEXT_LENGTH} characters).")

        try:
            size = int(size_part)
        except ValueError:
            size = _DEFAULT_SIZE
        if size not in ALLOWED_SIZES:
            size = _DEFAULT_SIZE

        return f"{size}::{text}"

    def normalize_input(self, cleaned_input: str) -> str:
        return cleaned_input

    def execute(self, normalized_input: str) -> ToolResult:
        size_str, _, text = normalized_input.partition("::")
        size = int(size_str)

        qr = qrcode.QRCode(box_size=1, border=4)
        qr.add_data(text)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        # NEAREST preserva os módulos como quadrados nítidos — um resize
        # suavizado poderia borrar o QR code a ponto de não ser mais legível.
        image = image.resize((size, size), Image.NEAREST)

        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        image_base64 = base64.b64encode(buffer.getvalue()).decode("ascii")

        return ToolResult(
            success=True,
            summary=f"QR code generated ({size}x{size}px).",
            data={
                "text": text,
                "size": size,
                "image_base64": image_base64,
            },
        )
