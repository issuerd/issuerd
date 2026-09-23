@echo off
echo Generating GitDiverge API client from OpenAPI spec...
cd /d "%~dp0"
..\target\release\issuerd.exe openapi -o openapi.json 
npx @hey-api/openapi-ts -f openapi-ts.config.ts
echo Done.
