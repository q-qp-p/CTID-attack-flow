<template>
  <div
    class="ai-generation"
    >
    <!-- Hide via visibility: hidden to preserve content size. -->
    <div :style="apiHealthCheckInProgress ? 'visibility: hidden' : ''">
        <h2 class="generation-title">
        Generate Attack Flow
        </h2>
        <div class="section source-type">
        <p class="section-title">
            SOURCE TYPE
        </p>
        <div
            class="button-grid source-type-grid"
            role="radiogroup"
            aria-label="Source type"
        >
            <div
            :class="['button', 'source-type-button', { selected: sourceType === 'upload' }]"
            role="radio"
            :aria-checked="sourceType === 'upload'"
            tabindex="0"
            @click="selectSourceType('upload')"
            @keydown.enter="selectSourceType('upload')"
            @keydown.space.prevent="selectSourceType('upload')"
            >
            <div class="button-header">
                <span class="button-icon"><EmptyPageIcon /></span>
                <p class="button-title">
                Upload Report PDF
                </p>
            </div>
            <p class="button-description">
                Create a flow from a security incident report PDF.
            </p>
            </div>
            <div
            :class="['button', 'source-type-button', { selected: sourceType === 'url' }]"
            role="radio"
            :aria-checked="sourceType === 'url'"
            tabindex="0"
            @click="selectSourceType('url')"
            @keydown.enter="selectSourceType('url')"
            @keydown.space.prevent="selectSourceType('url')"
            >
            <div class="button-header">
                <span class="button-icon"><LinkIcon /></span>
                <p class="button-title">
                Link to Report
                </p>
            </div>
            <p class="button-description">
                Paste a link to an incident report blog.
            </p>
            </div>
            <div
            :class="['button', 'source-type-button', { selected: sourceType === 'text' }]"
            role="radio"
            :aria-checked="sourceType === 'text'"
            tabindex="0"
            @click="selectSourceType('text')"
            @keydown.enter="selectSourceType('text')"
            @keydown.space.prevent="selectSourceType('text')"
            >
            <div class="button-header">
                <span class="button-icon"><FolderIcon /></span>
                <p class="button-title">
                Paste Text
                </p>
            </div>
            <p class="button-description">
                Paste an incident report as plain text.
            </p>
            </div>
        </div>
        </div>
        <div class="form-field source-data-field">
        <span class="section-title">SOURCE DATA</span>
        <div
            v-if="sourceType === 'upload'"
            class="source-upload-control"
        >
            <input
            :value="sourceFileName"
            type="text"
            placeholder="Select a PDF report."
            aria-label="Selected PDF report"
            disabled
            >
            <button
            class="source-upload-button"
            type="button"
            @click="openSourceFileDialog"
            >
            {{ sourceFile ? "Change PDF" : "Choose PDF" }}
            </button>
        </div>
        <input
            v-else-if="sourceType === 'url'"
            v-model="sourceUrl"
            type="url"
            placeholder="https://example.com/report"
            aria-label="Report URL"
            :aria-invalid="!!sourceUrl.trim() && !isSourceUrlValid"
            @keydown.stop
        >
        <textarea
            v-else-if="sourceType === 'text'"
            v-model="sourceText"
            rows="3"
            placeholder="Paste incident report text."
            aria-label="Report text"
            @keydown.stop
        />
        <input
            v-else
            type="text"
            aria-label="Source data"
            disabled
        >
        <input
            ref="sourceFileInput"
            class="file-input"
            type="file"
            accept=".pdf,application/pdf"
            @change="onSourceFileSelected"
        >
        </div>
        <div class="section llm-information">
        <p class="section-title">
            LLM INFORMATION <small>(optional)</small>
        </p>
        <div class="llm-container">
            <label class="form-field" style="flex: 1;">
                <span>TYPE:</span>
                <select
                    name="llm-provider-type"
                    v-model="llmType"
                    :class="llmType === '' ? 'empty' : ''"
                >
                    <option disabled selected hidden value="" key="none">Provider type</option>
                    <option v-for="providerType in RUNTIME_PROVIDER_OVERRIDE_TYPES" :key="providerType" :value="providerType">
                        {{ providerType }}
                    </option>
                </select>
            </label>
            <label class="form-field" style="flex: 2;">
                <span>ENDPOINT:</span>
                <input
                    v-model="llmEndpoint"
                    type="text"
                    placeholder="LLM endpoint override"
                    @keydown.stop
                >
            </label>
            <label class="form-field" style="flex: 2;">
                <span>TOKEN:</span>
                <input
                    v-model="llmToken"
                    type="password"
                    placeholder="LLM token override"
                    @keydown.stop
                >
            </label>
        </div>
        </div>
        <button
        class="generate-button"
        type="button"
        :disabled="!canGenerate"
        @click="onClickGenerate"
        >
            GENERATE
        </button>
        <div class="results-section">
            <div v-if="!flowGenerationRan">
                Flow generation results will appear here.
            </div>
            <div v-else-if="flowGenerationInProgress">
                Flow generation queued...
            </div>
            <div v-else-if="flowGenerationSucceeded">
                <div>Flow generation complete. Artifacts ready for download.</div>
                <div class="artifact-download-buttons-container">
                    <button
                        @click="() => downloadJobResultArtifact(flowGenerationCompletedJobId, 'afb', 'generated_flow.afb')"
                    >
                        AFB
                        <DownloadIcon></DownloadIcon>
                    </button>
                    <button
                        @click="downloadJobResultArtifact(flowGenerationCompletedJobId, 'stix', 'generated_flow_stix.json')"
                    >
                        STIX
                        <DownloadIcon></DownloadIcon>
                    </button>
                </div>
            </div>
            <div v-else>
                <div class="generation-error">Flow generation failed. Please try again.</div>
            </div>
        </div>
    </div>

    <div
        v-if="apiHealthCheckInProgress"
        class="health-check-loading-indicator"
    >
        <LoadingSpinner
            label="Detecting API"
        ></LoadingSpinner>
        <small>Detecting API...</small>
    </div>
    
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import LinkIcon from "@/components/Icons/LinkIcon.vue";
import FolderIcon from "@/components/Icons/FolderIcon.vue";
import EmptyPageIcon from "@/components/Icons/EmptyPageIcon.vue";
import {
    downloadJobResultArtifact,
    fetchJobResult,
    pollJob,
    RUNTIME_PROVIDER_OVERRIDE_TYPES,
    submitFileJob,
    submitPlaintextJob,
    submitUrlJob,
    type JobResultResponse,
    type JobSubmissionRequestOptions,
    type RuntimeProviderOverrideType,
    type SubmittedJob
} from "@/api/jobs";
import LoadingSpinner from "./LoadingSpinner.vue";
import { fetchHealthCheck } from "@/api/health.ts";
import DownloadIcon from "../Icons/DownloadIcon.vue";

type SourceType = "upload" | "url" | "text" | null;

export default defineComponent({
  name: "AIGenerationSplashScreen",
  setup() {
    return {
        RUNTIME_PROVIDER_OVERRIDE_TYPES
    }
  },
  data() {
    return {
      sourceType: null as SourceType,
      sourceFile: null as File | null,
      sourceFileName: "",
      sourceUrl: "",
      sourceText: "",
      llmType: "" as RuntimeProviderOverrideType | "",
      llmEndpoint: "",
      llmToken: "",
      apiHealthCheckInProgress: false,
      apiHealthCheckSucceeded: false,
      flowGenerationRan: false,
      flowGenerationInProgress: false,
      flowGenerationSucceeded: false,
      flowGenerationCompletedJobId: ""
    }
  },
  computed: {

    /**
     * Returns whether the report URL is valid enough for submission.
     * @returns
     *  True if the URL has a basic HTTP(S) shape.
     */
    isSourceUrlValid(): boolean {
      return /^https?:\/\/\S+$/.test(this.sourceUrl.trim());
    },

    /**
     * Returns whether the selected source type has source data.
     * @returns
     *  True if source data has been provided.
     */
    hasSourceData(): boolean {
      switch(this.sourceType) {
        case "upload":
          return this.sourceFile !== null;
        case "url":
          return this.isSourceUrlValid;
        case "text":
          return !!this.sourceText.trim();
        default:
          return false;
      }
    },

    /**
     * Returns whether the AI generation form can be submitted.
     * @returns
     *  True if the required generation inputs are populated.
     */
    canGenerate(): boolean {
      return !!(
        this.hasSourceData
        && !this.flowGenerationInProgress
      );
    }

  },
  async mounted() {
    this.apiHealthCheckInProgress = true;
    try {
        const res = await fetchHealthCheck();

        if (res.status === "ok") {
            this.apiHealthCheckSucceeded = true;
        }
    } catch (e) {
        console.error(e);
    }
    this.apiHealthCheckInProgress = false;

    if (this.apiHealthCheckSucceeded) {
        console.log("API health check succeeded. Using AFB API.");
    } else {
        console.log("API health check failed. Using LLM API.")
    }
  },
  methods: {

    /**
     * Selects the AI generation source type.
     * @param sourceType
     *  The selected source type.
     */
    selectSourceType(sourceType: Exclude<SourceType, null>) {
      if(this.sourceType !== sourceType) {
        this.clearSourceData();
      }
      this.sourceType = sourceType;
    },

    /**
     * Opens the report PDF file selection dialog.
     */
    openSourceFileDialog() {
      (this.$refs.sourceFileInput as HTMLInputElement | undefined)?.click();
    },

    /**
     * Updates the selected report PDF.
     * @param event
     *  The file input change event.
     */
    onSourceFileSelected(event: Event) {
      const input = event.target as HTMLInputElement;
      const file = input.files?.[0] ?? null;
      if(file && (file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf"))) {
        this.sourceFile = file;
        this.sourceFileName = file.name;
      } else {
        this.sourceFile = null;
        this.sourceFileName = "";
      }
      input.value = "";
    },

    /**
     * Clears the current source data.
     */
    clearSourceData() {
      this.sourceFile = null;
      this.sourceFileName = "";
      this.sourceUrl = "";
      this.sourceText = "";
    },

    async generateWithAfbApi() : Promise<JobResultResponse | null> {
        let submissionResponse : SubmittedJob | null = null;

        let requestOptions : JobSubmissionRequestOptions = {};

        if (this.llmType && this.llmEndpoint && this.llmToken) {
            requestOptions = {
                options: {
                    provider_override: {
                        provider_type: this.llmType,
                        endpoint: this.llmEndpoint,
                        api_key: this.llmToken
                    }
                }
            }
        }

        try {
            switch (this.sourceType) {
                case "text": {
                    if (this.sourceText) {
                        submissionResponse = await submitPlaintextJob(this.sourceText, requestOptions);
                    }
                    break;
                }
                case "upload": {
                    if (this.sourceFile) {
                        submissionResponse = await submitFileJob(this.sourceFile, requestOptions);
                    }
                    break;
                }
                case "url": {
                    if (this.sourceUrl) {
                        submissionResponse = await submitUrlJob(this.sourceUrl, requestOptions);
                    }
                    break;
                }
            }

            if (submissionResponse) {
                // First, poll until the job is complete.
                const cooldownMs = 1000;
                const maxRetries = 10;

                let currentTry = 1;

                let jobComplete = false;

                while (currentTry <= maxRetries) {
                    const pollRes = await pollJob(submissionResponse.poll_url);
                    console.debug(`Polling attempt ${currentTry}.`, pollRes);
                    if (pollRes.status === 'completed') {
                        jobComplete = true;
                        console.debug('Job completed.');
                        break;
                    } else if (pollRes.status === 'failed') {
                        console.debug('Job failed.');
                        break;
                    }
                    await new Promise(resolve => setTimeout(resolve, cooldownMs));
                    currentTry += 1;
                }

                // Then, fetch the job result.
                if (jobComplete) {
                    const result = await fetchJobResult(submissionResponse.job_id);
                    return result;
                } else {
                    throw new Error("Job did not complete.")
                }
            }
        } catch(e) {
            console.error(e);
        }

        return null;
    },

    async onClickGenerate() {
        this.flowGenerationRan = true;
        this.flowGenerationSucceeded = false;
        this.flowGenerationCompletedJobId = "";
        this.flowGenerationInProgress = true;
        
        if (this.apiHealthCheckSucceeded) {
            const result = await this.generateWithAfbApi();
            console.debug("Job result: ", result);
            if (result && result.status === "completed") {
                this.flowGenerationSucceeded = true;
                this.flowGenerationCompletedJobId = result.job_id
            }
        } else {
            console.log("TODO: Add LLM Typescript here.")
        }

        this.flowGenerationInProgress = false;
    },
    downloadJobResultArtifact

  },
  components: {
    EmptyPageIcon,
    FolderIcon,
    LinkIcon,
    LoadingSpinner,
    DownloadIcon
  }
});
</script>

<style scoped>
.ai-generation {
    position: relative;
}

.health-check-loading-indicator {
    position: absolute;
    top: 0;
    left: 0;
    text-align: center;
    width: 100%;
    height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
    flex-direction: column;
}

.generation-title {
  color: var(--af-text-color-primary);
  font-size: 13.5pt;
  font-weight: 700;
  margin-bottom: 18px;
}

.ai-generation .section {
  margin-bottom: 20px;
}

.ai-generation .results-section {
    text-align: center;
    color: var(--af-text-color-secondary);
}

.artifact-download-buttons-container {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 10px;
    gap: 10px;
}

.artifact-download-buttons-container button {
    border: 1px solid var(--af-border-color-primary);
    border-radius: 5px;
    background: none;
    padding: 3px 8px;
    color: var(--af-color-info);
}

.artifact-download-buttons-container button svg {
    fill: var(--af-color-info);
}

.generation-error {
    color: var(--af-color-error);
}

.source-type-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}

.button {
  border: solid 1px var(--af-border-color-primary);
  border-radius: 5px;
  box-sizing: border-box;
  padding: 24px;
  user-select: none;
}

.button:hover,
.source-type-button.selected {
  background: var(--af-border-color-primary);
}

.source-type-button.selected {
  border-color: var(--af-color-info);
}

.source-type-button:focus-visible {
  outline: solid 2px var(--af-color-info);
  outline-offset: 2px;
}

.button-header {
  align-items: center;
  display: flex;
  height: 17px;
  margin-bottom: 6px;
}

.button-icon {
  align-items: center;
  display: flex;
  height: 15px;
  justify-content: center;
  margin-right: 10px;
  width: 17px;
}

.button-icon svg {
  fill: var(--af-color-info);
}

.button-title {
  color: var(--af-color-info);
  font-size: 12.5pt;
  font-weight: 700;
  white-space: nowrap;
}

.button-description {
  color: var(--af-text-color-secondary);
  font-size: 10pt;
}

.section-title {
  color: var(--af-text-color-secondary);
  font-size: 9.5pt;
  font-weight: 500;
  margin-left: 2px;
  margin-bottom: 15px;
}

.form-field {
  color: var(--af-text-color-secondary);
  display: flex;
  flex-direction: column;
  font-size: 9.5pt;
  font-weight: 500;
  gap: 8px;
}

.form-field input,
.form-field textarea {
  background: var(--af-bg-color-primary);
  border: solid 1px var(--af-border-color-primary);
  border-radius: 5px;
  box-sizing: border-box;
  color: var(--af-text-color-primary);
  font-size: 10pt;
  height: 28px;
  padding: 4px 8px;
}

.form-field input:disabled,
.form-field textarea:disabled {
  color: var(--af-text-color-secondary);
}

.form-field textarea {
  height: 62px;
  line-height: 16px;
  overflow-y: auto;
  resize: none;
}

.form-field select {
    background: none;
    border: 1px solid var(--af-border-color-primary);
    border-radius: 5px;
    padding: 5px;
}

.form-field input::placeholder,
.form-field textarea::placeholder,
.form-field select.empty {
    color: var(--af-text-color-placeholder)
}

.source-upload-control {
  display: flex;
  gap: 8px;
}

.source-upload-control input {
  flex: 1;
}

.source-upload-button {
  background: var(--af-bg-color-primary);
  border: solid 1px var(--af-border-color-primary);
  border-radius: 5px;
  color: var(--af-color-info);
  font-size: 9.5pt;
  font-weight: 700;
  padding: 4px 12px;
  white-space: nowrap;
}

.source-upload-button:hover {
  background: var(--af-border-color-primary);
}

.file-input {
  display: none;
}

.source-data-field {
  margin-bottom: 20px;
}

.source-data-field .section-title {
  margin-bottom: 0px;
}

.llm-container {
  display: flex;
  gap: 28px;
}

.generate-button {
  background: var(--af-color-info);
  border: none;
  border-radius: 5px;
  color: #111;
  display: block;
  font-size: 9.5pt;
  font-weight: 700;
  height: 34px;
  margin: 24px auto 24px;
  min-width: 210px;
}

.generate-button:disabled {
  cursor: default;
  opacity: 0.7;
}
</style>
