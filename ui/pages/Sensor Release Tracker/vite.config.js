import react from '@vitejs/plugin-react-swc'

/** @type {import('vite').UserConfig} */
export default {
  plugins: [
    react()
  ],
  base: './',
  root: 'src',
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'shoelace': ['@shoelace-style/shoelace'],
          'foundry': ['@crowdstrike/foundry-js'],
        },
      },
    },
  },
};
