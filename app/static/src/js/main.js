import Alpine from "alpinejs";
import collapse from "@alpinejs/collapse";
import focus from "@alpinejs/focus";

import { sidebar } from "./components/sidebar.js";
import { toolSearch } from "./components/tool-search.js";
import { jobStatus } from "./components/job-status.js";
import { copyButton } from "./components/copy.js";
import { mathCaptcha } from "./components/captcha-math.js";
import { toast } from "./components/toast.js";

Alpine.plugin(collapse);
Alpine.plugin(focus);

Alpine.data("sidebar", sidebar);
Alpine.data("toolSearch", toolSearch);
Alpine.data("jobStatus", jobStatus);
Alpine.data("copyButton", copyButton);
Alpine.data("mathCaptcha", mathCaptcha);
Alpine.data("toast", toast);

window.Alpine = Alpine;
Alpine.start();
