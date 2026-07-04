import { createServer, type Server } from "node:http";

import { DEV_TRACE_DEFAULT_PORT, listDevTraceEvents, devTraceHasCredentials } from "./trace-buffer.js";
import { devTraceResponseHeaders } from "./trace-security-headers.js";
import { loadDevTraceDashboardHtml } from "./trace-ui.js";

export type DevTraceServerOptions = {
  port?: number;
  host?: string;
  cwd?: string;
  envFile?: string;
  hasCredentials?: boolean;
  onListen?: (url: string) => void;
};

export async function startDevTraceServer(options: DevTraceServerOptions = {}): Promise<Server> {
  const port = options.port ?? DEV_TRACE_DEFAULT_PORT;
  const host = options.host ?? "127.0.0.1";
  const cwd = options.cwd ?? process.cwd();
  const hasCredentials =
    options.hasCredentials ??
    devTraceHasCredentials({ cwd, envFile: options.envFile });
  const dashboardHtml = loadDevTraceDashboardHtml();

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://${host}:${port}`);
    const events = listDevTraceEvents(cwd);

    if (url.pathname === "/api/events") {
      res.writeHead(200, devTraceResponseHeaders("application/json; charset=utf-8"));
      res.end(
        JSON.stringify(
          {
            events,
            has_credentials: hasCredentials,
          },
          null,
          2,
        ),
      );
      return;
    }

    if (url.pathname === "/" || url.pathname.startsWith("/runs/")) {
      res.writeHead(200, devTraceResponseHeaders("text/html; charset=utf-8"));
      res.end(dashboardHtml);
      return;
    }

    res.writeHead(404, devTraceResponseHeaders("text/plain; charset=utf-8"));
    res.end("Not found");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      options.onListen?.(`http://${host}:${port}`);
      resolve();
    });
  });

  return server;
}
