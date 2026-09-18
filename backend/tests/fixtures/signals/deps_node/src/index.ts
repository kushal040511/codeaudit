import fs from "node:fs";
import React from "react";
import { Button } from "@scope/ui/button";
import express from "express";
import chalk from "chalk"; // imported but not declared

export function start(): void {
  const app = express();
  console.log(chalk.green(String(React.version)), Button, fs.existsSync("."));
  app.listen(3000);
}
