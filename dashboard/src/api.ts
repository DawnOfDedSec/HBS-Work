import type {
  AuthUser,
  Campaign,
  IngestResult,
  Issuance,
  Location,
  OverviewMetrics,
  Report,
  TreatmentState,
} from "./types";
import type {
  NetworkDeviceDetail,
  NetworkDeviceSummary,
  NetworkDiffResponse,
  NetworkReportDetail,
  NetworkTreatmentHistoryEntry,
  NetworkUploadResult,
} from "./network-types";
import { serializeFilters, type ScopeFilters } from "./filters";

export type ApiErrorBody = { error?: string; code?: string };

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export type ApiClientOptions = { baseUrl?: string; fetch?: typeof fetch };

/** Typed client for the dashboard API. Cookies are sent same-origin. */
export class ApiClient {
  private readonly baseUrl: string;
  private readonly doFetch: typeof fetch;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? "";
    this.doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Call any endpoint with a caller-supplied response type. */
  raw<T>(method: string, path: string, body?: unknown): Promise<T> {
    return this.request<T>(method, path, body);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {    const init: RequestInit = { method, credentials: "include" };
    if (body !== undefined) {
      init.headers = { "content-type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const response = await this.doFetch(`${this.baseUrl}${path}`, init);
    if (response.status === 204) return undefined as T;
    const text = await response.text();
    let parsed: unknown = undefined;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new ApiError(response.status, "INVALID_JSON", text.slice(0, 200));
      }
    }
    if (!response.ok) {
      const err = (parsed ?? {}) as ApiErrorBody;
      throw new ApiError(response.status, err.code ?? `HTTP_${response.status}`, err.error ?? response.statusText);
    }
    return parsed as T;
  }

  // --- auth ---
  authStatus() {
    return this.request<{ initialized: boolean; user?: AuthUser; role?: string }>("GET", "/api/auth/status");
  }

  setup(username: string, password: string) {
    return this.request<{ user: AuthUser }>("POST", "/api/auth/setup", { username, password });
  }

  login(username: string, password: string) {
    return this.request<{ user: AuthUser }>("POST", "/api/auth/login", { username, password });
  }

  logout() {
    return this.request<void>("POST", "/api/auth/logout");
  }

  // --- campaigns & locations ---
  listCampaigns() {
    return this.request<Campaign[]>("GET", "/api/campaigns");
  }

  createCampaign(input: {
    name: string;
    client?: string;
    scope?: string;
    expiry?: string;
    tags?: string[];
    location?: { name: string; tags?: string[] };
  }) {
    return this.request<Campaign & { locations?: Location[]; downloadToken?: string; pushToken?: string }>(
      "POST",
      "/api/campaigns",
      {
        name: input.name,
        client: input.client,
        scope: input.scope,
        expiry: input.expiry,
        tags: input.tags,
        locations: input.location ? [input.location] : undefined,
      },
    );
  }

  listLocations(campaignId: number) {
    return this.request<Location[]>("GET", `/api/campaigns/${campaignId}/locations`);
  }

  createLocation(campaignId: number, input: { name: string; tags?: string[] }) {
    return this.request<Location>("POST", `/api/campaigns/${campaignId}/locations`, input);
  }

  retireLocation(campaignId: number, locationId: number) {
    return this.request<Location>("PATCH", `/api/campaigns/${campaignId}/locations/${locationId}`, {
      retired: true,
    });
  }

  // --- issuances & downloads ---
  listIssuances(campaignId: number, locationId: number) {
    return this.request<Issuance[]>("GET", `/api/campaigns/${campaignId}/locations/${locationId}/issuances`);
  }

  createIssuance(campaignId: number, locationId: number, input: { platform: string; expiry?: string }) {
    return this.request<Issuance & { downloadUrl: string }>(
      "POST",
      `/api/campaigns/${campaignId}/locations/${locationId}/issuances`,
      input,
    );
  }

  revokeIssuance(campaignId: number, extractorId: string, reason: string) {
    return this.request<{ revoked: true }>(
      "DELETE",
      `/api/campaigns/${campaignId}/issuances/${extractorId}`,
      { reason },
    );
  }

  downloadUrl(issuanceId: string) {
    return `${this.baseUrl}/api/issuances/${issuanceId}/download`;
  }

  // --- reports / findings ---
  overview(filters?: ScopeFilters) {
    const query = filters ? serializeFilters(filters) : "";
    return this.request<OverviewMetrics>("GET", `/api/overview${query ? `?${query}` : ""}`);
  }

  listFindings(filters: ScopeFilters) {
    const query = serializeFilters(filters);
    return this.request<{ results: unknown[] }>("GET", `/api/findings${query ? `?${query}` : ""}`);
  }

  getReport(reportId: number) {
    return this.request<Report>("GET", `/api/reports/${reportId}`);
  }

  updateTreatment(reportId: number, checkId: string, input: { state: TreatmentState; justification?: string; assignee?: string; dueDate?: string }) {
    return this.request<{ state: TreatmentState }>(
      "POST",
      `/api/reports/${reportId}/findings/${encodeURIComponent(checkId)}/treatment`,
      input,
    );
  }

  // --- upload ---
  async uploadReports(files: File[] | { name: string; bytes: Uint8Array }[]): Promise<{ results: { name: string; result: IngestResult }[] }> {
    const form = new FormData();
    for (const file of files) {
      if (file instanceof File) form.append("files", file, file.name);
      else form.append("files", new Blob([file.bytes as unknown as BlobPart]), file.name);
    }
    const response = await this.doFetch(`${this.baseUrl}/api/reports/upload`, {
      method: "POST",
      body: form,
      credentials: "include",
    });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) : {};
    if (!response.ok) {
      throw new ApiError(response.status, parsed.code ?? `HTTP_${response.status}`, parsed.error ?? response.statusText);
    }
    return parsed;
  }

  // --- network device / firewall config review ---
  async uploadNetworkConfigs(
    campaignId: number,
    locationId: number,
    files: File[],
  ): Promise<{ results: { name: string; result: NetworkUploadResult }[] }> {
    const form = new FormData();
    form.append("campaignId", String(campaignId));
    form.append("locationId", String(locationId));
    for (const file of files) form.append("files", file, file.name);
    const response = await this.doFetch(`${this.baseUrl}/api/network/upload`, {
      method: "POST",
      body: form,
      credentials: "include",
    });
    const text = await response.text();
    const parsed = text ? JSON.parse(text) : {};
    if (!response.ok) {
      throw new ApiError(response.status, parsed.code ?? `HTTP_${response.status}`, parsed.error ?? response.statusText);
    }
    return parsed;
  }

  listNetworkDevices(filter: { campaignId?: number; locationId?: number }) {
    const key = filter.locationId !== undefined ? `locationId=${filter.locationId}` : `campaignId=${filter.campaignId}`;
    return this.request<{ devices: NetworkDeviceSummary[] }>("GET", `/api/network/devices?${key}`);
  }

  getNetworkDevice(deviceId: number) {
    return this.request<NetworkDeviceDetail>("GET", `/api/network/devices/${deviceId}`);
  }

  getNetworkReport(reportId: number) {
    return this.request<NetworkReportDetail>("GET", `/api/network/reports/${reportId}`);
  }

  updateNetworkTreatment(
    reportId: number,
    checkId: string,
    input: { state: TreatmentState; justification?: string; assignee?: string; dueDate?: string },
  ) {
    return this.request<{ reportId: number; checkId: string; state: TreatmentState; updatedAt: string }>(
      "POST",
      `/api/network/reports/${reportId}/findings/${encodeURIComponent(checkId)}/treatment`,
      input,
    );
  }

  getNetworkTreatmentHistory(reportId: number, checkId: string) {
    return this.request<{ reportId: number; checkId: string; history: NetworkTreatmentHistoryEntry[] }>(
      "GET",
      `/api/network/reports/${reportId}/findings/${encodeURIComponent(checkId)}/history`,
    );
  }

  bulkUpdateNetworkTreatment(
    reportId: number,
    input: { checkIds: string[]; state: TreatmentState; justification?: string; assignee?: string; dueDate?: string },
  ) {
    return this.request<{
      reportId: number;
      state: TreatmentState;
      applied: Array<{ checkId: string; state: TreatmentState; historyId: number }>;
      skipped: Array<{ checkId: string; reason: string }>;
    }>("POST", `/api/network/reports/${reportId}/findings/treatment-bulk`, input);
  }

  getNetworkDiff(deviceId: number, params: { from?: number; to?: number } = {}) {
    const query = new URLSearchParams();
    if (params.from !== undefined) query.set("from", String(params.from));
    if (params.to !== undefined) query.set("to", String(params.to));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return this.request<NetworkDiffResponse>("GET", `/api/network/devices/${deviceId}/diff${suffix}`);
  }

  networkExportUrl(kind: "report" | "device", id: number, format: "xlsx" | "csv") {
    return `${this.baseUrl}/api/network/${kind === "report" ? "reports" : "devices"}/${id}/export?format=${format}`;
  }

  deleteNetworkDevice(deviceId: number) {
    return this.request<{ deleted: boolean; deviceId: number }>("DELETE", `/api/network/devices/${deviceId}`);
  }

  exportUrl(scope: "report" | "campaign", id: number, format: "xlsx" | "csv" | "pdf" | "docx") {
    return `${this.baseUrl}/api/export/${scope}/${id}?format=${format}`;
  }
}

export const api = new ApiClient();
