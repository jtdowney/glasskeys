# Build all projects
build:
    cd glasslock && gleam build
    cd glasskey && gleam build
    cd example/backend && gleam build
    cd example/frontends/lustre && gleam build
    cd example/frontends/svelte && bun run build

# Test all projects
test:
    cd glasslock && gleam test
    cd glasskey && gleam test

# Format all projects
fmt:
    cd glasslock && gleam format src test
    cd glasskey && gleam format src test
    cd example/backend && gleam format src
    cd example/frontends/lustre && gleam format src
    cd example/frontends/svelte && bun run format

# Generate docs for each project
docs:
    cd glasslock && gleam docs build --open
    cd glasskey && gleam docs build --open

# Download all dependencies
deps:
    cd glasslock && gleam deps download
    cd glasskey && gleam deps download
    cd example/backend && gleam deps download
    cd example/frontends/lustre && gleam deps download
    cd example/frontends/svelte && bun install

# Run the shared example backend
example-backend:
    cd example/backend && gleam run

# Run the Lustre frontend dev server
example-lustre-frontend:
    cd example/frontends/lustre && gleam run -m lustre/dev start

# Run the Lustre example (backend + frontend) in parallel
[parallel]
example-lustre: example-backend example-lustre-frontend

# Run the Svelte frontend dev server
example-svelte-frontend:
    cd example/frontends/svelte && bun run dev

# Run the Svelte example (backend + frontend) in parallel
[parallel]
example-svelte: example-backend example-svelte-frontend

# Update all dependencies
update-deps:
    cd glasslock && gleam deps update
    cd glasskey && gleam deps update
    cd example/backend && gleam deps update
    cd example/frontends/lustre && gleam deps update
    cd example/frontends/svelte && bun update
