<template>
  <div
    class="multiselect-field-control"
    :class="{ column: direction === 'column' }"
  >
    <button
      v-for="opt in options"
      :key="opt.value as string"
      type="button"
      class="option"
      :class="[{ active: isSelected(opt.value as string) }, { dim: opt.feature === false }]"
      :aria-pressed="isSelected(opt.value as string)"
      :disabled="disabled"
      @click="toggle(opt.value as string)"
    >
      <span
        class="checkmark"
        aria-hidden="true"
      >
        {{ isSelected(opt.value as string) ? '✓' : '' }}
      </span>
      <span class="label">{{ opt.text }}</span>
    </button>
  </div>
</template>

<script lang="ts">
import * as EditorCommands from "@OpenChart/DiagramEditor";
import { defineComponent, type PropType } from "vue";
import type { OptionItem } from "@/assets/scripts/Browser";
import type { ListProperty, MultiSelectProperty } from "@OpenChart/DiagramModel";
import type { SynchronousEditorCommand } from "@OpenChart/DiagramEditor";

export default defineComponent({
  name: "MultiSelectField",
  props: {
    property: {
      // Support new MultiSelectProperty as the data model
      type: Object as PropType<MultiSelectProperty>,
      required: true
    },
    featuredOptions: {
      type: Set as PropType<Set<string>>,
      required: false,
      default: () => new Set<string>()
    },
    disabled: {
      type: Boolean,
      default: false
    },
    // Layout direction for the rendered options
    direction: {
      type: String as PropType<"row" | "column">,
      default: "column"
    }
  },
  emits: {
    execute: (cmd: SynchronousEditorCommand) => cmd
  },
  computed: {
    /**
     * Build options from the MultiSelectProperty's options list.
     */
    options(): OptionItem<string>[] {
      const optionsProp: ListProperty | undefined = this.property.options;
      const options: OptionItem<string>[] = [];
      if (!optionsProp) {
        return options;
      }
      const fo = this.featuredOptions;
      for (const [value, prop] of optionsProp.value) {
        const text = prop.toString();
        const feat = fo ? fo.has(value) : true;
        options.push({ value, text, feature: feat });
      }
      // Feature-first sort, consistent with other fields
      options.sort((a,b) => {
        if (a.feature && !b.feature) return -1;
        if (!a.feature && b.feature) return 1;
        return 0;
      });
      return options;
    },

    /**
     * Current selection derived from MultiSelectProperty.
     */
    selectedValues(): Set<string> {
      return new Set<string>(this.property.values as Iterable<string>);
    }
  },
  methods: {
    isSelected(value: string): boolean {
      return this.selectedValues.has(value);
    },
    toggle(value: string) {
      if (this.disabled) return;
      const next = new Set(this.selectedValues);
      if (next.has(value)) {
        next.delete(value);
      } else {
        next.add(value);
      }
      const out = Array.from(next);
      const cmd = EditorCommands.setMultiSelectProperty(this.property, out);
      this.$emit("execute", cmd);
    }
  }
});
</script>

<style scoped>
.multiselect-field-control {
  display: flex;
  flex-direction: column;
  flex-wrap: nowrap;
  gap: 6px;
  color: #cccccc;
}
.multiselect-field-control.column {
  flex-direction: column;
}
.option {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: #cccccc;
  font-size: 10pt;
  padding: 6px 10px;
  min-height: 32px;
  border: solid 1px #3d3d3d;
  border-radius: 4px;
  background: #2e2e2e;
  cursor: pointer;
  user-select: none;
  width: 100%;
  box-sizing: border-box;
}
.option.dim {
  color: #8c8c8c;
}
.option.active {
  color: #e6e6e6;
  background: #3a3a3a;
  border-color: #4a4a4a;
}
.option:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.checkmark {
  width: 1em;
  text-align: center;
}
.label {
  white-space: nowrap;
  text-overflow: ellipsis;
  overflow: hidden;
}
</style>
