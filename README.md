# Cyber AI - Security Scanner

A comprehensive security scanning tool powered by AI that helps identify and analyze potential vulnerabilities in web applications and infrastructure.

## Prerequisites

- Node.js 18+ (for frontend)
- Python 3.10+ (for backend)
- Docker (optional, for containerized setup)
- pnpm (for frontend package management)

## Environment Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd cyber-ai
```

2. Set up environment variables:
```bash
# Copy the example env files
cp .env.example .env
cp frontend/.env.example frontend/.env

# Edit both .env files with your configuration
# Required variables:
# - OPENAI_API_KEY
# - NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
# - CLERK_SECRET_KEY
# - MONGODB_URI (remote MongoDB connection string)
```

## Running with Docker

1. Make sure Docker and Docker Compose are installed and running
2. Build and start all services:
```bash
docker compose up --build
```

The following services will be available:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000

## Running Services Separately

### Backend Setup

1. Create and activate a Python virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

2. Install backend dependencies:
```bash
pip install -r src/requirements.txt
```

3. Start the backend server:
```bash
cd src
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

1. Install frontend dependencies:
```bash
cd frontend
pnpm install
```

2. Start the development server:
```bash
pnpm dev
```

### Database Configuration

The application uses MongoDB for data storage. By default, it connects to a remote MongoDB instance using the connection string specified in the `.env` file.

#### Remote MongoDB (Default)
- Set the `MONGODB_URI` environment variable in your `.env` file to your remote MongoDB connection string
- No additional setup required

#### Local MongoDB (Optional - for VPC deployment)
To use a local MongoDB instance instead:

1. Uncomment the MongoDB services in `docker-compose.yml`:
   - Uncomment the `mongodb` service
   - Uncomment the `volumes` section
   - Update the MongoDB credentials as needed

2. Update the `MONGODB_URI` in `.env` to point to the local instance:
```bash
MONGODB_URI=mongodb://admin:password@mongodb:27017/cyber_ai
```

## Development Notes

- The backend API documentation is available at http://localhost:8000/docs
- The frontend uses Next.js 14 with App Router
- Authentication is handled by Clerk

## Troubleshooting

### Docker Issues
- If Docker containers hang during build:
  1. Stop all containers: `docker compose down`
  2. Clean Docker cache: `docker system prune -af --volumes`
  3. Restart Docker Desktop
  4. Rebuild: `docker compose up --build`

### Frontend Issues
- If styles are not loading:
  1. Clear `.next` cache: `cd frontend && rm -rf .next`
  2. Reinstall dependencies: `pnpm install`
  3. Rebuild: `pnpm build`
  4. Start dev server: `pnpm dev`

### Backend Issues
- If scanner modules fail:
  1. Check Python virtual environment is activated
  2. Verify all system dependencies are installed
  3. Check MongoDB connection string in `.env`
  4. Verify environment variables are set correctly

## API Documentation

The backend API provides the following main endpoints:

- `GET /api/v1/scans` - List all scans
- `POST /api/v1/scans` - Start a new scan
- `GET /api/v1/scans/{scan_id}` - Get scan details
- `GET /api/v1/reports` - List all reports
- `GET /api/v1/reports/{report_id}` - Get report details

For full API documentation, visit http://localhost:8000/docs when the backend is running.
