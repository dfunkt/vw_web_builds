// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { parse } from "tldts";

async function isAllowedByRor(
  rpId: string,
  origin: string
): Promise<boolean> {
  const maxLabels = 5;

  try {
    const response = await fetch(
      `https://${rpId}/.well-known/webauthn`,
      {
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!response.ok) {
      return false;
    }

    const contentType = response.headers.get("content-type");
    if (!contentType || !contentType.includes("application/json")) {
      return false;
    }

    const data = (await response.json()) as { origins?: unknown };

    if (
      !data ||
      !Array.isArray(data.origins) ||
      !data.origins.every(o => typeof o === "string") ||
      data.origins.length === 0
    ) {
      return false;
    }

    const labelsSeen = new Set<string>();

    for (const originItem of data.origins) {
      try {
        const url = new URL(originItem);

        const hostname = url.hostname;
        if (!hostname) continue;

        const parsed = parse(hostname, { allowPrivateDomains: true });
        if (!parsed.domain || !parsed.publicSuffix) continue;

        const label = parsed.domain.slice(
          0,
          parsed.domain.length - parsed.publicSuffix.length - 1
        );

        if (!label) continue;

        if (labelsSeen.size >= maxLabels && !labelsSeen.has(label)) {
          continue;
        }

        if (origin === originItem) {
          return true;
        }

        if (labelsSeen.size < maxLabels) {
          labelsSeen.add(label);
        }
      } catch {
        continue;
      }
    }
    
    return false;
  } catch {
    return false;
  }
}

export async function isValidRpId(
  rpId: string,
  origin: string
): Promise<boolean> {
  const parsedOrigin = parse(origin, { allowPrivateDomains: true });
  const parsedRpId = parse(rpId, { allowPrivateDomains: true });

  const classicMatch =
    (parsedOrigin.domain == null &&
      parsedOrigin.hostname == parsedRpId.hostname &&
      parsedOrigin.hostname == "localhost") ||
    (parsedOrigin.domain != null &&
      parsedOrigin.domain == parsedRpId.domain &&
      parsedOrigin.subdomain.endsWith(parsedRpId.subdomain));

  if (classicMatch) {
    return true;
  }

  return await isAllowedByRor(rpId, origin);
}
