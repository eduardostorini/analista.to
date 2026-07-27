class ToolValidationError(ValueError):
    """Levantada por `BaseTool.validate_input` quando a entrada do usuário é inválida."""

    def __init__(self, message: str, field_name: str = "input"):
        super().__init__(message)
        self.field_name = field_name


class ToolExecutionError(RuntimeError):
    """Levantada por `BaseTool.execute` para falhas conhecidas e reportáveis ao usuário."""

    def __init__(self, message: str, error_code: str = "execution_error"):
        super().__init__(message)
        self.error_code = error_code
