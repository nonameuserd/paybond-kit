export type OutputFormat = "table" | "json";

export type ColorMode = "auto" | "always" | "never";

export type ErrorCategory =
  | "usage"
  | "auth"
  | "forbidden"
  | "validation"
  | "not_found"
  | "gone"
  | "confirmation_required"
  | "rate_limit"
  | "gateway"
  | "network"
  | "environment"
  | "internal";

export type CliErrorDetails = Record<string, unknown>;

export type CliErrorShape = {
  category: ErrorCategory;
  code: string;
  message: string;
  details?: CliErrorDetails;
};

export type CliEnvelope<T> = {
  ok: boolean;
  command: string;
  data: T | null;
  warnings: string[];
  request_id: string;
  error: CliErrorShape | null;
};

export type GlobalOptions = {
  gateway: string;
  envFile: string;
  format: OutputFormat;
  color: ColorMode;
  profile?: string;
  requestId: string;
  yes: boolean;
  noOpen: boolean;
  /** Comma-separated field names for automation output (`--json`). */
  jsonFields?: string;
  /** jq-style filter expression (`--jq`). */
  jqExpr?: string;
};

export type Writable = { write(chunk: string): boolean };

export type CliDependencies = {
  cwd?: string;
  fetch?: typeof fetch;
  stdout?: Writable;
  stderr?: Writable;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  openBrowser?: (url: string) => Promise<boolean>;
};

export type CommandResult<T = Record<string, unknown>> = {
  data: T;
  warnings?: string[];
};

export const EXIT_SUCCESS = 0;
export const EXIT_FAILURE = 1;
export const EXIT_AUTH = 2;
export const EXIT_FORBIDDEN = 3;
export const EXIT_CONFIRMATION = 4;
export const EXIT_GATEWAY = 5;
export const EXIT_ENVIRONMENT = 6;

export class CliError extends Error {
  readonly category: ErrorCategory;
  readonly code: string;
  readonly exitCode: number;
  readonly details?: CliErrorDetails;

  constructor(
    message: string,
    options: {
      category?: ErrorCategory;
      code?: string;
      exitCode?: number;
      details?: CliErrorDetails;
    } = {},
  ) {
    super(message);
    this.name = "CliError";
    this.category = options.category ?? "usage";
    this.code = options.code ?? `cli.${this.category}`;
    this.exitCode = options.exitCode ?? exitCodeForCategory(this.category);
    this.details = options.details;
  }
}

export function exitCodeForCategory(category: ErrorCategory): number {
  switch (category) {
    case "auth":
      return EXIT_AUTH;
    case "forbidden":
      return EXIT_FORBIDDEN;
    case "confirmation_required":
      return EXIT_CONFIRMATION;
    case "gateway":
    case "rate_limit":
    case "network":
      return EXIT_GATEWAY;
    case "environment":
      return EXIT_ENVIRONMENT;
    default:
      return EXIT_FAILURE;
  }
}

export function exitCodeForHttpStatus(status: number): { exitCode: number; category: ErrorCategory } {
  if (status === 401) {
    return { exitCode: EXIT_AUTH, category: "auth" };
  }
  if (status === 403) {
    return { exitCode: EXIT_FORBIDDEN, category: "forbidden" };
  }
  if (status === 404) {
    return { exitCode: EXIT_FAILURE, category: "not_found" };
  }
  if (status === 410) {
    return { exitCode: EXIT_FAILURE, category: "gone" };
  }
  if (status === 429) {
    return { exitCode: EXIT_GATEWAY, category: "rate_limit" };
  }
  if (status >= 500) {
    return { exitCode: EXIT_GATEWAY, category: "gateway" };
  }
  return { exitCode: EXIT_FAILURE, category: "validation" };
}
