<template>
  <div class="object-recommender-menu-control">
    <div class="menu-head">
      <input
        class="search-field"
        ref="search"
        type="text"
        placeholder="Search..."
        v-model="value"
        @keydown="onKeyDown"
      >
    </div>
    <div class="menu-body">
      <ScrollListBox
        ref="scrollbox"
        class="recommendations"
        :items="items"
        :item-display-count="7"
        @scroll="i => active = items[i].id"
      >
        <template #up>
          ^
        </template>
        <template #item="{ item }">
          <div
            class="recommendation"
            @click="submitSelection(item.id)"
          >
            <div class="title">
              <div
                class="dot"
                :style="{ background: item.color }"
              />
              <div class="name">
                {{ item.name }}
              </div>
            </div>
          </div>
        </template>
        <template #down>
          v
        </template>
      </ScrollListBox>
    </div>
  </div>
</template>

<script lang="ts">
// Dependencies
import { defineComponent, type PropType } from 'vue';
import type { ObjectRecommendation, ObjectRecommender } from "@OpenChart/DiagramEditor";
// Components
import ScrollListBox from '@/components/Containers/ScrollListBox.vue';

export default defineComponent({
  name: 'ObjectRecommenderMenu',
  props: {
    recommender: {
      type: Object as PropType<ObjectRecommender>,
      required: true
    }
  },
  data() {
    return {
      value: "",
      items: [] as ObjectRecommendation[],
      active: null as string | null
    }
  },
  methods: {

    /**
     * Search keydown behavior.
     * @param event
     *  The keydown event.
     */
    onKeyDown(event: KeyboardEvent) {
      // Cast scrollbox
      const scrollbox = this.$refs.scrollbox as {
        shiftSelection(delta: number): void
      }
      // Update window
      switch(event.key) {
        case "ArrowUp":
          event.preventDefault();
          scrollbox.shiftSelection(-1);
          break;
        case "ArrowDown":
          event.preventDefault();
          scrollbox.shiftSelection(1);
          break;
        case "Enter":
          event.preventDefault();
          if(this.active) {
            this.submitSelection(this.active);
          }
          break;
        default:
          this.updateRecommendations();
          break;
      }
    },

    /**
     * Submits the selection.
     * @param id
     *  The item's id.
     */
    submitSelection(id: string) {
      const item = this.items.find(o => o.id === id);
      if(item) {
        this.$emit("select", item.id)
      }
    },

    /**
     * Updates the list of recommendations.
     */
    async updateRecommendations() {
      // Get recommendations
      const recs = await this.recommender.getRecommendations(this.value);
      // Update recommendations
      this.items = recs.items;
    },

  },
  emits: {
    select: (item_id: string) => item_id,
    focusout: () => true,
  },
  async mounted() {
    const search = this.$refs.search as HTMLInputElement;
    // Focus search
    search.focus();
    // Update recommendations
    this.updateRecommendations();
  },
  components: { ScrollListBox }
});
</script>

<style scoped>

/** === Main Control === */

.object-recommender-menu-control {
  display: flex;
  flex-direction: column;
  box-shadow: 0px 0px 10px 0px #00000066;
  border-radius: 10px;
  z-index: 1;
}

.menu-head {
  display: flex;
  padding: 5px 8px;
  border-color: var(--af-border-color-secondary);
  border-width: 1px;
  border-style: solid solid none solid;
  border-top-left-radius: 5px;
  border-top-right-radius: 5px;
  background: var(--af-bg-color-secondary);
}

.menu-body {
  padding: 0px 6px;
  border-color: var(--af-border-color-secondary);
  border-width: 1px;
  border-style: none solid solid solid;
  border-bottom-left-radius: 5px;
  border-bottom-right-radius: 5px;
  background: var(--af-bg-color-primary);
}

/** === Menu Head === */

.search-field {
  width: 100%;
  font-size: 10pt;
  font-family: "Inter";
  color: var(--af-text-color-primary);
  background: none;
  border: none;
  border-radius: 3px;
  padding: 6px;
  outline: none;
  box-sizing: border-box;
}

/** === Menu Body === */

.recommendations {
  display: flex;
  flex-direction: column;
}

.recommendations:deep(.up-indicator),
.recommendations:deep(.down-indicator) {
  display: flex;
  justify-content: center;
  height: 10px;
  color: var(--af-text-color-primary)
}

.active .recommendation {
  background: var(--af-bg-color-tertiary);
}

.recommendation {
  padding: 5px 8px;
  border-radius: 3px;
  box-sizing: border-box;
}

.recommendation .title {
  display: flex;
  align-items: center;
  margin-bottom: 2px;
}

.recommendation .dot {
  width: 8px;
  height: 8px;
  margin-right: 6px;
}

.recommendation .name {
  font-family: "Inter";
  font-weight: 700;
  font-size: 13px;
  text-transform: uppercase;
  color: var(--af-text-color-primary);
}

.recommendation .subtitle {
  font-family: "Inter";
  font-size: 10pt;
  color: var(--af-text-color-secondary);
}

</style>
