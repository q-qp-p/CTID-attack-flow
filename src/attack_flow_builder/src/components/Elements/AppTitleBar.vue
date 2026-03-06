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
    <div
        class="tlp-marking"
        v-if="tlpMarking && tlpMarking.value"
        :data-value="tlpMarking.value"
    >
        {{ tlpMarking.toString() }}
    </div>
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
import { EnumProperty } from "@/assets/scripts/OpenChart/DiagramModel";

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

    tlpMarking(): EnumProperty | undefined {
        return this.application.activeEditor.file.canvas.properties
            .get("tlp_marking")
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
        if(cmd instanceof Promise) {
          this.application.execute(await cmd);
        } else {
          this.application.execute(cmd);
        }
      } catch(ex: unknown) {
        console.error(ex);
      }
    }

  },
  components: { TitleBar }
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

.tlp-marking {
    position: absolute;
    left: 50%;
    transform: translateX(-50%);
    height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: black;
    font-weight: 600;
    padding: 0 5px 0 5px;
}

.tlp-marking[data-value="tlp-red"] {
    color: #FF2B2B;
}
.tlp-marking[data-value="tlp-amber"] {
    color: #FFC000;
}
.tlp-marking[data-value="tlp-green"] {
    color: #33FF00;
}
.tlp-marking[data-value="tlp-clear"] {
    color: #FFFFFF;
}

</style>
