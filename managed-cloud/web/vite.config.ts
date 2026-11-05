import { defineConfig } from 'vitest/config';
export default defineConfig({build:{sourcemap:false},test:{environment:'jsdom',environmentOptions:{jsdom:{url:'https://local.invalid'}},include:['tests/**/*.test.tsx','tests/**/*.test.ts'],setupFiles:['./tests/setup.ts']}});
