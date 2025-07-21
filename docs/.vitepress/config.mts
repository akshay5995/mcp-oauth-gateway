import { defineConfig, MarkdownOptions } from 'vitepress'
import MermaidExample from '../mermaid-markdown-all'


const allMarkdownTransformers: MarkdownOptions = {
  config: (md) => {
    MermaidExample(md);
  },
};

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: 'MCP OAuth Gateway',
  description: 'OAuth 2.1 authorization server for Model Context Protocol (MCP) services',

  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }],
    ['meta', { name: 'theme-color', content: '#3eaf7c' }],
    ['meta', { name: 'apple-mobile-web-app-capable', content: 'yes' }],
    ['meta', { name: 'apple-mobile-web-app-status-bar-style', content: 'black' }]
  ],

  themeConfig: {
    nav: [
      { text: 'Quick Start', link: '/quick-start' },
      { text: 'Architecture', link: '/architecture' },
      { 
        text: 'Links',
        items: [
          { text: 'GitHub', link: 'https://github.com/akshay5995/mcp-oauth-gateway' },
          { text: 'Development Guide', link: 'https://github.com/akshay5995/mcp-oauth-gateway/blob/main/CLAUDE.md' },
          { text: 'MCP Specification', link: 'https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization' }
        ]
      }
    ],

    sidebar: [
      { text: 'Quick Start', link: '/quick-start' },
      { text: 'Architecture & Design', link: '/architecture' }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/akshay5995/mcp-oauth-gateway' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2025 MCP OAuth Gateway Contributors'
    },

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/akshay5995/mcp-oauth-gateway/edit/main/docs/:path'
    },

    lastUpdated: {
      text: 'Updated at',
      formatOptions: {
        dateStyle: 'full',
        timeStyle: 'medium'
      }
    }
  },

  markdown: allMarkdownTransformers,
})