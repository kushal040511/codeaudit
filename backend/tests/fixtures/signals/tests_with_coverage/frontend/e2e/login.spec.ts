import { test, expect } from "@playwright/test";

test("login page", async ({ page }) => {
  await page.goto("/login");
  await expect(page).toHaveTitle(/Login/);
});
