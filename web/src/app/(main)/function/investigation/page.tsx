"use client";

import { useContext, useEffect } from "react";

import { InvestigationMode } from "@/components/investigation-mode";

import { AuthorityTab } from "../tasks/detail/_tabs/authority-tab";

// A portable casefile remains inspectable when its original live task is gone.
export default function InvestigationPage() {
  const [, setOffline] = useContext(InvestigationMode);
  useEffect(() => () => setOffline(false), [setOffline]);
  return <AuthorityTab taskId="" onOfflineChange={setOffline} />;
}
