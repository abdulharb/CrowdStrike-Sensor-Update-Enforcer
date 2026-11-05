import react from '@vitejs/plugin-react-swc'

// Unmodified Foundry React blueprint config. noAttr() strips `crossorigin`
// from the built index.html, which Foundry's sandboxed iframe requires.
const noAttr = () => ({
  name: 'no-attribute',
  transformIndexHtml(html) {
    return html.replace(/ crossorigin(?:="[^"]*")?/g, '')
  }
})

/** @type {import('vite').UserConfig} */
export default {
  plugins: [
    react(),
    noAttr()
  ],
  root: 'src',
  base: './'
};
