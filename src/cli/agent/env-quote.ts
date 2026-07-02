export function quoteEnvValue(value: string): string {
  if (/^[A-Za-z0-9_./:@+-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}
