# AI Vulnerability Triage & Attack-Path Prioritizer

A local-first security triage dashboard for normalizing scanner outputs, correlating findings into attack paths, prioritizing remediations, and presenting a risk-focused assessment workflow.

## Features

- Upload and normalize scanner reports from multiple formats
- Deduplicate findings across similar alerts
- Prioritize vulnerabilities by exploitability and business risk
- Build and visualize multi-step attack paths
- Review remediation recommendations and report metrics
- Designed for Vercel-style serverless deployment via API routes

## Tech stack

- React + Vite
- TypeScript
- Express-compatible serverless route structure
- Gemini API integration for AI-assisted triage
- Supabase-ready persistence layer

## Prerequisites

- Node.js 18+
- A Gemini API key
- A Supabase project (for persistent storage in Vercel deployment)

## Local setup

1. Install dependencies:
   `npm install`
2. Create a local environment file from [.env.example](.env.example) and fill in the values.
3. Start the app:
   `npm run dev`

## Environment variables

Copy [.env.example](.env.example) to `.env.local` and configure:

- `GEMINI_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`
- `APP_URL`

## Vercel deployment

This project is structured for Vercel serverless routes under [api](api). For hosted deployment, add the same variables in your Vercel environment settings and connect the app to a Supabase database.

## Project status

This repo is intended to be used as a GitHub project and can be adapted for either:

- local development with a local runtime store
- serverless deployment on Vercel with Supabase persistence

## Notes

- The app includes a fallback heuristic path when Gemini is not configured.
- A production-ready hosted setup should use a real database rather than the runtime in-memory store for persistence.
