# Cyber AI - Security Scanner

TODO: Mock data switch on/off for demo purposes


A modern security scanning platform with an AI-powered analysis engine. Features a beautiful Next.js frontend and a powerful Python backend.

## Features

- 🔍 Multiple scanning modules:
  - Domain Information
  - Subdomain Discovery
  - Port Scanning
  - Technology Detection
  - WAF Detection
  - URL Fuzzing
  - Vulnerability Scanning
- 🤖 AI-powered analysis and reporting
- 📊 Beautiful dashboard with real-time updates
- 🌙 Dark mode support
- 🚀 Modern tech stack: Next.js 14, FastAPI, TanStack Query

## Prerequisites

- Python 3.8+
- Node.js 18+
- pnpm (recommended) or npm
- OpenAI API key

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cyber-ai.git
cd cyber-ai
```

2. Install backend dependencies:
```bash
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
pnpm install
cd ..
```

4. Set up environment variables:

Create a `.env` file in the root directory:
```bash
OPENAI_API_KEY=your_openai_api_key
```

Create a `.env` file in the `frontend` directory:
```bash
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=your_clerk_publishable_key
CLERK_SECRET_KEY=your_clerk_secret_key
NEXT_PUBLIC_CLERK_SIGN_IN_URL=/sign-in
NEXT_PUBLIC_CLERK_SIGN_UP_URL=/sign-up
NEXT_PUBLIC_CLERK_AFTER_SIGN_IN_URL=/
NEXT_PUBLIC_CLERK_AFTER_SIGN_UP_URL=/
```

## Running the Application

You can start both the frontend and backend with a single command:

```bash
./dev.sh
```

Or run them separately:

### Backend
```bash
cd src
python3 -m uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
pnpm dev
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## Project Structure

```
.
├── frontend/               # Next.js frontend
│   ├── src/
│   │   ├── app/           # Next.js app router
│   │   ├── components/    # React components
│   │   └── lib/          # Utilities and API client
│   └── public/           # Static assets
├── src/                  # Python backend
│   ├── agents/          # AI agents
│   ├── scanners/        # Security scanning modules
│   └── main.py          # FastAPI application
└── data/                # Scan results and reports
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
