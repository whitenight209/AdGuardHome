import { defineConfig } from 'orval';

export default defineConfig({
    sso: {
        input: {
            target: '../openapi/sso.yaml',
        },
        output: {
            target: './src/features/sso/api/generated.ts',
            schemas: './src/features/sso/api/model',
            client: 'fetch',
            baseUrl: 'control',
            prettier: true,
            override: {
                header: false,
                mutator: {
                    path: './src/api/customFetch.ts',
                    name: 'customFetch',
                },
                fetch: {
                    includeHttpResponseReturnType: false,
                },
                enumGenerationType: 'union',
            },
        },
    },
});
