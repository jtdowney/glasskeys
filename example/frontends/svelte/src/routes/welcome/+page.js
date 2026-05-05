import { redirect } from "@sveltejs/kit";

export function load() {
  const username = sessionStorage.getItem("username");
  if (!username) {
    redirect(307, "/");
  }

  return { username };
}
