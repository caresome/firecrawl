import { AuthResponse } from "../../src/types";
import { logger } from "./logger";
import * as Sentry from "@sentry/node";
import { configDotenv } from "dotenv";
import { config } from "../config";
configDotenv();

let warningCount = 0;

export function withAuth<T, U extends any[]>(
  originalFunction: (...args: U) => Promise<T>,
  mockSuccess: T,
) {
  return async function (...args: U): Promise<T> {
    const useDbAuthentication = config.USE_DB_AUTHENTICATION;
    if (!useDbAuthentication) {
      // Self-hosted API key protection - only check on request objects (has headers)
      if (config.FIRECRAWL_API_KEY) {
        const possibleReq = args[0] as any;
        // Only check API key if first arg looks like a request object (has headers)
        if (possibleReq?.headers) {
          const authHeader = possibleReq.headers.authorization;
          const token = authHeader?.split(" ")[1];
          if (token !== config.FIRECRAWL_API_KEY) {
            return { success: false, error: "Unauthorized: Invalid API key", status: 401 } as T;
          }
        }
      }

      if (warningCount < 5) {
        logger.warn("You're bypassing authentication");
        warningCount++;
      }
      return { success: true, ...(mockSuccess || {}) } as T;
    } else {
      return await originalFunction(...args);
    }
  };
}
