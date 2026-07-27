<template>
  <select
    name="llm-provider-type"
    v-model="model"
    :class="model === '' ? 'empty' : ''"
  >
    <option
      disabled
      selected
      hidden
      value=""
      key="placeholder"
    >
      Provider type
    </option>
    <option
      value=""
      key="none"
    >
      (none)
    </option>
    <option
      v-for="providerType in RUNTIME_PROVIDER_OVERRIDE_TYPES"
      :key="providerType"
      :value="providerType"
    >
      {{ providerType }}
    </option>
  </select>
</template>
<script setup lang="ts">
import { RUNTIME_PROVIDER_OVERRIDE_TYPES } from '@/api/jobs';
const model = defineModel<string>()

</script>
<style scoped>
select {
    background: var(--af-bg-color-primary);
    border: 1px solid var(--af-border-color-primary);
    border-radius: 5px;
    color: var(--af-text-color-primary);
    padding: 5px;
    color: var(--af-text-color-primary);
}

select.empty {
    color: var(--af-text-color-placeholder)
}
</style>
