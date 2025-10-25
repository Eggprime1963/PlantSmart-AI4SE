# Shopping Cart Unit Testing Project

This project demonstrates comprehensive unit testing of a shopping cart implementation using Jest.

## Project Structure

```
project/
├── src/
│   └── shoppingCart.js       # Core shopping cart implementation
├── tests/
│   ├── shoppingCart.test.js  # Unit tests
│   └── mocks/
│       └── productService.mock.js  # Mock services
├── coverage/
│   └── index.html           # Test coverage report
├── prompts/
│   └── log.md              # Development log and notes
└── README.md
```

## Features Tested

- Adding items to cart
- Removing items from cart
- Updating item quantities
- Calculating cart total
- Applying discounts
- Clearing cart

## Running Tests

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run tests in watch mode
npm test -- --watch
```

## Test Coverage

The project aims for high test coverage with particular focus on:
- Happy path scenarios
- Edge cases
- Error conditions
- External service integration

## Development Approach

The project follows a test-driven development (TDD) approach:
1. Write failing test
2. Implement feature
3. Refactor code
4. Verify tests pass

## Dependencies

- Jest: Testing framework
- Mock implementations for external services
