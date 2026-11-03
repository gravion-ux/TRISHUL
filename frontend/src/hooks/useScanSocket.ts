import { useEffect, useRef, useState } from "react";
import { scanSocketUrl } from "../api";
import type { ScanEvent } from "../types";

export interface ScanSocketOptions {
  scanId: string | null;
  token: string | null;
  /** Keep the stream open (and reconnect) while the scan is still running. */
  active: boolean;
  onEvent: (event: ScanEvent) => void;
}

export interface ScanSocketState {
  connected: boolean;
  attempts: number;
  error: string | null;
}

const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 10000;

/**
 * Opens the scan WebSocket, decodes contract events and reconnects with a
 * capped exponential backoff while the scan is still running.
 */
export function useScanSocket({
  scanId,
  token,
  active,
  onEvent,
}: ScanSocketOptions): ScanSocketState {
  const [connected, setConnected] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const onEventRef = useRef(onEvent);
  onEventRef.current = onEvent;

  useEffect(() => {
    if (!scanId || !token || !active) {
      setConnected(false);
      return;
    }

    let disposed = false;
    let socket: WebSocket | null = null;
    let timer: number | null = null;
    let attempt = 0;

    const open = (): void => {
      if (disposed) {
        return;
      }
      let next: WebSocket;
      try {
        next = new WebSocket(scanSocketUrl(scanId, token));
      } catch {
        setError("Could not open the scan stream.");
        attempt += 1;
        setAttempts(attempt);
        timer = window.setTimeout(open, Math.min(INITIAL_BACKOFF_MS * 2 ** (attempt - 1), MAX_BACKOFF_MS));
        return;
      }
      socket = next;

      next.onopen = () => {
        attempt = 0;
        setAttempts(0);
        setConnected(true);
        setError(null);
      };
      next.onmessage = (event: MessageEvent<string>) => {
        try {
          const parsed = JSON.parse(event.data) as ScanEvent;
          onEventRef.current(parsed);
        } catch {
          setError("Received a malformed scan event.");
        }
      };
      next.onerror = () => {
        setError("Scan stream connection error.");
      };
      next.onclose = () => {
        setConnected(false);
        if (disposed) {
          return;
        }
        attempt += 1;
        setAttempts(attempt);
        const delay = Math.min(INITIAL_BACKOFF_MS * 2 ** (attempt - 1), MAX_BACKOFF_MS);
        timer = window.setTimeout(open, delay);
      };
    };

    open();

    return () => {
      disposed = true;
      if (timer !== null) {
        window.clearTimeout(timer);
      }
      socket?.close();
    };
  }, [scanId, token, active]);

  return { connected, attempts, error };
}
