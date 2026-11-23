import packageJson from "../../package.json";

import { t } from "@/i18n";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Wolftrax",
  version: packageJson.version,
  copyright: `© ${currentYear}, ARTEX.`,
  meta: {
    title: t("Wolftrax — Investigation Lab"),
    description: t("Console for the LLM-driven autonomous penetration testing system"),
  },
};
