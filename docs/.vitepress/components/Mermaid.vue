<template>
  <div class="mermaid-container">
    <div v-if="showCode" class="mermaid-code">
      <details>
        <summary>Show Mermaid Code</summary>
        <pre><code>{{ decodedGraph }}</code></pre>
      </details>
    </div>
    <div :id="id" class="mermaid-diagram" v-html="renderedMermaid"></div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, watch, nextTick } from 'vue'
import { useData } from 'vitepress'
import mermaid from 'mermaid'

const props = defineProps<{
  id: string
  graph: string
  showCode?: boolean
}>()

const { isDark } = useData()
const renderedMermaid = ref('')

const decodedGraph = computed(() => {
  try {
    return decodeURIComponent(props.graph)
  } catch {
    return props.graph
  }
})

const getMermaidConfig = (isDarkMode: boolean) => ({
  startOnLoad: false,
  theme: isDarkMode ? 'dark' : 'default',
  securityLevel: 'loose',
  fontFamily: 'inherit',
  fontSize: 14,
  themeVariables: {
    // Ensure text is visible in both themes
    primaryColor: isDarkMode ? '#4f46e5' : '#3b82f6',
    primaryTextColor: isDarkMode ? '#f1f5f9' : '#1e293b',
    primaryBorderColor: isDarkMode ? '#6366f1' : '#2563eb',
    lineColor: isDarkMode ? '#64748b' : '#475569',
    sectionBkgColor: isDarkMode ? '#1e293b' : '#f8fafc',
    altSectionBkgColor: isDarkMode ? '#334155' : '#e2e8f0',
    gridColor: isDarkMode ? '#475569' : '#cbd5e1',
    secondaryColor: isDarkMode ? '#374151' : '#e5e7eb',
    tertiaryColor: isDarkMode ? '#4b5563' : '#d1d5db',
    background: isDarkMode ? '#0f172a' : '#ffffff',
    mainBkg: isDarkMode ? '#1e293b' : '#f8fafc',
    secondBkg: isDarkMode ? '#334155' : '#e2e8f0',
  },
  flowchart: {
    useMaxWidth: true,
    htmlLabels: true,
    curve: 'basis'
  },
  sequence: {
    useMaxWidth: true,
    wrap: true
  },
  gantt: {
    useMaxWidth: true
  }
})

const renderDiagram = async () => {
  try {
    // Re-initialize mermaid with current theme
    mermaid.initialize(getMermaidConfig(isDark.value))

    const graphDefinition = decodedGraph.value
    const uniqueId = `${props.id}_${isDark.value ? 'dark' : 'light'}_${Date.now()}`
    
    // Render the mermaid diagram
    const { svg } = await mermaid.render(uniqueId, graphDefinition)
    renderedMermaid.value = svg
  } catch (error) {
    console.error('Failed to render Mermaid diagram:', error)
    renderedMermaid.value = `<div class="mermaid-error">
      <p><strong>Failed to render Mermaid diagram</strong></p>
      <pre>${decodedGraph.value}</pre>
    </div>`
  }
}

// Watch for theme changes and re-render
watch(isDark, () => {
  nextTick(() => {
    renderDiagram()
  })
})

onMounted(() => {
  renderDiagram()
})
</script>

<style scoped>
.mermaid-container {
  margin: 1rem 0;
}

.mermaid-code {
  margin-bottom: 1rem;
}

.mermaid-code details {
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  padding: 0.5rem;
  background: var(--vp-c-bg-alt);
}

.mermaid-code summary {
  cursor: pointer;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.mermaid-code pre {
  margin: 0.5rem 0 0 0;
  padding: 0;
  background: transparent;
  border: none;
}

.mermaid-code code {
  font-family: var(--vp-font-family-mono);
  font-size: 0.875rem;
  color: var(--vp-c-text-1);
}

.mermaid-diagram {
  text-align: center;
  background: var(--vp-c-bg);
  border-radius: 6px;
  padding: 1rem;
  border: 1px solid var(--vp-c-divider);
}

.mermaid-diagram :deep(svg) {
  max-width: 100%;
  height: auto;
}

.mermaid-error {
  color: var(--vp-c-danger-1);
  background: var(--vp-c-danger-soft);
  border: 1px solid var(--vp-c-danger-2);
  border-radius: 6px;
  padding: 1rem;
}

.mermaid-error pre {
  background: transparent;
  color: var(--vp-c-text-1);
  font-size: 0.875rem;
}
</style>