<template>
  <div class="app-title-bar-container">
    <TitleBar
      class="app-title-bar-element"
      :menus="menus"
      @select="onItemSelect"
    >
      <template #icon>
        <span class="logo">
          <img
            alt="Logo"
            title="Logo"
            :src="icon"
          >
        </span>
      </template>
    </TitleBar>
    <ClassificationMarking />
  </div>
</template>

<script lang="ts">
import Configuration from "@/assets/configuration/app.configuration";
// Dependencies
import { defineComponent } from "vue";
import { useApplicationStore } from "@/stores/ApplicationStore";
import { useContextMenuStore } from "@/stores/ContextMenuStore";
import type { CommandEmitter } from "@/assets/scripts/Application";
import type { ContextMenuSubmenu } from "@/assets/scripts/Browser";
// Components
import TitleBar from "@/components/Controls/TitleBar.vue";
import ClassificationMarking from "./ClassificationMarking.vue";

export default defineComponent({
  name: "AppTitleBar",
  data() {
    return {
      application: useApplicationStore(),
      contextMenus: useContextMenuStore(),
      icon: Configuration.application_icon
    };
  },
  computed: {

    /**
     * Returns the application's menus.
     * @returns
     *  The application's menus.
     */
    menus(): ContextMenuSubmenu<CommandEmitter>[] {
      return [
        this.contextMenus.fileMenu,
        this.contextMenus.editMenu,
        this.contextMenus.viewMenu,
        this.contextMenus.helpMenu
      ]
    },

    classificationMarking(): EnumProperty | undefined {
      const tup: TupleProperty | undefined = this.application.activeEditor.file.canvas.properties.get("classification")
      if (!tup) {
        return undefined;
      }
      const result: EnumProperty | undefined = tup?.value.get("marking") as EnumProperty;
      return result
    },

    classificationGroup(): StringProperty | undefined {
      const tup: TupleProperty | undefined = this.application.activeEditor.file.canvas.properties.get("classification")
      if (!tup) {
        return undefined;
      }
      const result: StringProperty | undefined = tup?.value.get("group") as StringProperty;
      return result
    }
  },
  methods: {

    /**
     * Menu item selection behavior.
     * @param emitter
     *  Menu item's command emitter.
     */
    async onItemSelect(emitter: CommandEmitter) {
      try {
        const cmd = emitter();
        if (cmd instanceof Promise) {
          this.application.execute(await cmd);
        } else {
          this.application.execute(cmd);
        }
      } catch (ex: unknown) {
        console.error(ex);
      }
    }

  },
  components: { TitleBar, ClassificationMarking }
});
</script>

<style scoped>
/** === App Logo === */

.logo {
  margin: 5px 6px 0px 12px;
}

.logo img {
  height: 16px;
}

.app-title-bar-container {
    display: flex;
    position: relative;
    z-index: 2; /* Make sure find-dialog hides underneath title bar. */
}

</style>
