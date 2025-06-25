.PHONY: all build test deploy security-scan clean

# Build variables
DOCKER_REGISTRY = localhost:5000
VERSION = 1.0.0
BUILD_DATE = $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

all: security-scan build test

build:
	@echo "Building PCI compliant backend..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--no-cache \
		-f docker/Dockerfile.secure \
		-t $(DOCKER_REGISTRY)/pci-backend:$(VERSION) .

test:
	@echo "Running security tests..."
	python -m pytest tests/security_tests.py -v
	python -m pytest tests/compliance_tests.py -v

security-scan:
	@echo "Running security scans..."
	# Static code analysis
	bandit -r src/ -f json -o reports/bandit-report.json
	
	# Dependency scanning
	safety check --json > reports/safety-report.json
	
	# Container scanning
	trivy image --severity HIGH,CRITICAL \
		$(DOCKER_REGISTRY)/pci-backend:$(VERSION)

deploy-dev:
	@echo "Deploying to development environment..."
	docker-compose -f docker/docker-compose.yml up -d

deploy-prod:
	@echo "Deploying to production environment..."
	@echo "WARNING: This requires physical access to air-gapped system"
	@echo "1. Export images to encrypted media"
	@echo "2. Transfer media to secure facility"
	@echo "3. Import and deploy in isolated environment"
	
	# Export images
	docker save -o pci-backend-$(VERSION).tar \
		$(DOCKER_REGISTRY)/pci-backend:$(VERSION)
	
	# Encrypt the export
	gpg --encrypt --recipient pci-admin@company.com \
		--cipher-algo AES256 \
		pci-backend-$(VERSION).tar

audit-report:
	@echo "Generating compliance audit report..."
	python scripts/generate_audit_report.py \
		--start-date $(shell date -d '7 days ago' '+%Y-%m-%d') \
		--end-date $(shell date '+%Y-%m-%d') \
		--output reports/pci-audit-$(shell date '+%Y%m%d').pdf

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf reports/
	docker system prune -f

backup:
	@echo "Creating encrypted backup..."
	tar czf - /secure/audit /secure/tokens | \
		gpg --symmetric --cipher-algo AES256 > \
		backup-$(shell date '+%Y%m%d-%H%M%S').tar.gz.gpg

restore:
	@echo "Restoring from backup..."
	@echo "This requires manual verification and dual-person integrity"