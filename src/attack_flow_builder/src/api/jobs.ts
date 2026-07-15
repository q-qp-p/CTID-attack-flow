import { API_BASE_URL } from "@/config/api";

export type JobSubmissionMetadata = Record<string, unknown>;
export type JobSubmissionOptionsPayload = Record<string, unknown>;

export interface JobSubmissionRequestOptions {
  metadata?: JobSubmissionMetadata;
  options?: JobSubmissionOptionsPayload;
  signal?: AbortSignal;
}

export interface JobPollRequestOptions {
  signal?: AbortSignal;
}

export interface SubmittedJob {
  job_id: string;
  status: string;
  submitted_at: string;
  poll_url: string;
  request_id: string;
}

interface ApiErrorResponse {
  error?: {
    code?: string;
    message?: string;
  };
}

/**
 * Submits a new plaintext job to the Attack Flow API.
 * @param text
 *  The report text to submit for extraction.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
export async function submitPlaintextJob(
  text: string,
  requestOptions: JobSubmissionRequestOptions = {}
): Promise<SubmittedJob> {
  return submitJsonJob(
    {
      input_type: "text",
      text
    },
    requestOptions
  );
}

/**
 * Submits a new URL-backed job to the Attack Flow API.
 * @param url
 *  The report URL to submit for asynchronous retrieval and extraction.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
export async function submitUrlJob(
  url: string,
  requestOptions: JobSubmissionRequestOptions = {}
): Promise<SubmittedJob> {
  return submitJsonJob(
    {
      input_type: "url",
      url
    },
    requestOptions
  );
}

/**
 * Submits a new file upload job to the Attack Flow API.
 * @param file
 *  The file to upload as multipart form data.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
export async function submitFileJob(
  file: File,
  requestOptions: JobSubmissionRequestOptions = {}
): Promise<SubmittedJob> {
  const formData = new FormData();
  formData.set("file", file);

  if(requestOptions.metadata) {
    formData.set("metadata", JSON.stringify(requestOptions.metadata));
  }

  if(requestOptions.options) {
    formData.set("options", JSON.stringify(requestOptions.options));
  }

  const response = await fetch(JOBS_URL, {
    method: "POST",
    body: formData,
    signal: requestOptions.signal
  });

  return parseSubmittedJob(response);
}

/**
 * Polls a submitted job status URL.
 * @param pollUrl
 *  The poll URL returned by the jobs submission response.
 * @param requestOptions
 *  Optional abort signal for cancelling the request.
 * @returns
 *  The parsed polling response payload.
 */
export async function pollJob(
  pollUrl: string,
  requestOptions: JobPollRequestOptions = {}
): Promise<unknown> {
  const response = await fetch(buildPollUrl(pollUrl), {
    method: "GET",
    signal: requestOptions.signal
  });

  return parseApiResponse(response);
}

/**
 * Submits a JSON-backed text or URL job request.
 * @param body
 *  The JSON payload required by the jobs endpoint.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
async function submitJsonJob(
  body: {
    input_type: "text" | "url";
    text?: string;
    url?: string;
  },
  requestOptions: JobSubmissionRequestOptions
): Promise<SubmittedJob> {
  const response = await fetch(JOBS_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      ...body,
      ...(requestOptions.metadata ? { metadata: requestOptions.metadata } : {}),
      ...(requestOptions.options ? { options: requestOptions.options } : {})
    }),
    signal: requestOptions.signal
  });

  return parseSubmittedJob(response);
}

const JOBS_URL = `${API_BASE_URL.replace(/\/+$/, "")}/jobs`;

/**
 * Resolves a poll URL against the configured API base URL when needed.
 * @param pollUrl
 *  The relative or absolute poll URL returned by the API.
 * @returns
 *  The absolute poll URL to request.
 */
function buildPollUrl(pollUrl: string): string {
  return new URL(pollUrl, `${API_BASE_URL.replace(/\/+$/, "")}/`).toString();
}

/**
 * Parses and validates a queued job submission response.
 * @param response
 *  The HTTP response returned by the jobs endpoint.
 * @returns
 *  The validated queued job response payload.
 */
async function parseSubmittedJob(response: Response): Promise<SubmittedJob> {
  const payload = await parseApiResponse(response);

  if(!isSubmittedJob(payload)) {
    throw new Error("jobs submission response did not include a valid job identifier");
  }

  return payload;
}

/**
 * Parses an API response and throws a normalized error for non-success responses.
 * @param response
 *  The HTTP response returned by the API.
 * @returns
 *  The parsed response payload.
 */
async function parseApiResponse(response: Response): Promise<unknown> {
  const payload = await parseResponseBody(response);

  if(!response.ok) {
    const apiError = payload as ApiErrorResponse | null;
    const errorCode = apiError?.error?.code?.trim();
    const errorMessage = apiError?.error?.message?.trim();
    throw new Error(errorCode && errorMessage ? `${errorCode}: ${errorMessage}` : errorMessage || response.statusText);
  }

  return payload;
}

/**
 * Parses a response body as JSON when possible.
 * @param response
 *  The HTTP response whose body should be parsed.
 * @returns
 *  The parsed response payload, or null when the body is empty.
 */
async function parseResponseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") || "";
  if(contentType.includes("application/json")) {
    return response.json();
  }

  const text = await response.text();
  return text ? JSON.parse(text) as unknown : null;
}

/**
 * Returns whether a parsed payload matches the queued job response shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required submitted job fields.
 */
function isSubmittedJob(payload: unknown): payload is SubmittedJob {
  if(!payload || typeof payload !== "object") {
    return false;
  }

  const candidate = payload as Record<string, unknown>;
  return (
    typeof candidate.job_id === "string"
    && typeof candidate.status === "string"
    && typeof candidate.submitted_at === "string"
    && typeof candidate.poll_url === "string"
    && typeof candidate.request_id === "string"
  );
}
