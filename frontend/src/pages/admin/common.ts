import { ApiError, type Role } from "../../api";

export const ROLES: Role[] = ["user", "advanced", "admin"];
export const ROLE_LABEL: Record<Role, string> = { user: "User", advanced: "Advanced user", admin: "Administrator" };
export const msg = (e: unknown) => (e instanceof ApiError ? e.message : "Unexpected error");
export const usersChanged = () => window.dispatchEvent(new Event("lsx:users-changed"));
