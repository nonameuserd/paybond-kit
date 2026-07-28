import { createServer, type Server } from "node:http";

import { DEV_TRACE_DEFAULT_PORT, listDevTraceEvents, devTraceHasCredentials } from "./trace-buffer.js";
import { isAllowedDevTraceHost } from "./trace-host.js";
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
    const bound = server.address();
    const boundPort = bound && typeof bound === "object" ? bound.port : port;
    if (!isAllowedDevTraceHost(req.headers.host, boundPort)) {
      res.writeHead(403, devTraceResponseHeaders("text/plain; charset=utf-8"));
      res.end("Forbidden host");
      return;
    }
    if (req.method !== undefined && req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, {
        ...devTraceResponseHeaders("text/plain; charset=utf-8"),
        allow: "GET, HEAD",
      });
      res.end("Method not allowed");
      return;
    }

    const url = new URL(req.url ?? "/", `http://${host}:${boundPort}`);
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
      const address = server.address();
      const listenPort = address && typeof address === "object" ? address.port : port;
      options.onListen?.(`http://${host}:${listenPort}`);
      resolve();
    });
  });

  return server;
}
