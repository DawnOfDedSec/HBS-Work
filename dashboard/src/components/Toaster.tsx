import type { ReactNode } from "react";
import { ToastProvider } from "./ui/toast";

export { useToast } from "./ui/toast";
export type { ToastAction, ToastApi, ToastOptions, ToastTone } from "./ui/toast";

/**
 * Global toast provider. Mount once near the root; call `useToast()` anywhere
 * below it to surface success / error / info notifications from mutations.
 */
export function Toaster({ children }: { children: ReactNode }) {
  return <ToastProvider>{children}</ToastProvider>;
}
