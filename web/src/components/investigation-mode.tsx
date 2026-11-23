"use client";

import { createContext, type Dispatch, type SetStateAction } from "react";

// The task header and the global pending-approvals badge share this flag with
// Authority so opening a historical case stops their live reads as well.
export const InvestigationMode = createContext<[boolean, Dispatch<SetStateAction<boolean>>]>([false, () => {}]);
