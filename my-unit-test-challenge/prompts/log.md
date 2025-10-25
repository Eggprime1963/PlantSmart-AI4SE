1. Analyze the following Node.js file and produce a detailed breakdown of all functions that need **unit testing**.

For EACH function, identify and describe the following points clearly:

1. **Main Functionality** – What the function does, in 1–2 concise sentences.
2. **Input Parameters and Types** – List every parameter (e.g., req, res, user) and describe its type (Object, String, Boolean, etc.).
3. **Expected Return Values** – Describe what the function returns or responds with (e.g., HTTP JSON response, token string, transporter object).
4. **Potential Edge Cases** – List edge or failure cases that should be covered in unit tests (e.g., invalid email, expired token, missing password).
5. **Dependencies that Need Mocking** – Identify external services, libraries, or models that must be mocked during testing (e.g., jwt, bcrypt, nodemailer, User model, SystemLog, emailService, process.env).

❌ Do NOT write test cases or change any code.
✅ Only analyze and describe testing requirements and dependencies.

Use clear headings for each function:
### Function: <function_name>
<detailed analysis>

The file to analyze is:
<PASTE YOUR CODE HERE>

2. 💡 **Task:**  
    Generate complete Jest unit tests for **all functions** in the provided JavaScript file using the **test case matrix (full_unit_test_matrix.md)**.

    🧰 **Project Context:**
    - JavaScript source file: `authController.js`
    - Test case reference: `full_unit_test_matrix.md`
    - Testing framework: **Jest**
    - Environment: Node.js (CommonJS modules)
    - Location: `/tests/authController.test.js`

    ---

    ### ✅ **Requirements**

    1. **Use Jest framework**
    - Include proper setup and teardown blocks:
        ```js
        beforeAll(() => { /* setup mocks or env vars */ });
        beforeEach(() => { jest.clearAllMocks(); });
        afterAll(() => { jest.restoreAllMocks(); });
        ```
    2. **Cover every function** listed in `full_unit_test_matrix.md`, including:
    - `createTransporter`
    - `generateToken`
    - `forgotPassword`
    - `resetPassword`
    - `changePassword`
    - `register`
    - `sendWelcomeEmail`
    - `login`
    - `logout`

    3. **Mock all external dependencies**:
    - `nodemailer`, `jsonwebtoken`, `bcryptjs`, `../models`, `../services/emailService`
    - Use `jest.mock()` and mock resolved/rejected promises where needed.

    4. **Assertions**
    - Use descriptive assertions like:
        ```js
        expect(result).toBeDefined();
        expect(mockFn).toHaveBeenCalledWith(...);
        expect(() => fn()).toThrow("expected error");
        expect(response.status).toEqual(400);
        ```
    - Validate both **happy path** and **error conditions** using mocks and `async/await`.

    5. **Descriptive test names**
    - Follow this pattern:
        ```js
        describe('forgotPassword()', () => {
        it('should return 400 when email is missing', async () => { ... });
        });
        ```

    6. **Reference matrix for completeness**
    - Ensure each test case from `full_unit_test_matrix.md` maps to a corresponding `it()` block.
    - Example:
        ```js
        it('[FP_02] should return 400 when email is missing', async () => { ... });
        ```

    7. **Organize by function**
    - Group tests with `describe()` per function name.
    - Maintain alphabetical order of functions for consistency.

    8. **Environment variables**
    - Mock `process.env` values as needed for JWT, email credentials, etc.:
        ```js
        process.env.JWT_SECRET = 'test-secret';
        process.env.EMAIL_USER = 'test@example.com';
        ```

    9. **Error simulation**
    - Use `mockRejectedValueOnce()` for async errors.
    - Ensure `toThrow` and `toMatch` assertions cover expected failure messages.

---

3. Generate comprehensive **unit test cases** for each function in the following Node.js module.

🧪 Requirements:
- Write tests using Jest syntax (or Mocha/Chai if preferred).
- Cover all major branches, including:
  - ✅ Happy path scenarios (successful execution)
  - ⚠️ Edge cases (boundary and input validation)
  - ❌ Error scenarios (e.g., exceptions, invalid data)
  - 🔗 Integration with the cart or user state, where applicable

🧱 For each function, include:
1. **Test suite name** (`describe`) – same as the function name.
2. **Individual test cases** (`it`) – one for each logical branch or outcome.
3. **Mocking setup** for external dependencies (e.g., `jwt`, `bcrypt`, `nodemailer`, `User`, `SystemLog`, `emailService`).
4. **Arrange-Act-Assert pattern** to structure each test.
5. Use **realistic sample data** and payloads for requests/responses.
6. Validate all responses or return values using proper assertions (`expect`).

🧰 Output Format:
Use this structure:
------------------------------------------------------------
### Function: <function_name>

```js
describe('<function_name>', () => {
  it('should <do something> when <condition>', async () => {
    // Arrange
    ...
    // Act
    ...
    // Assert
    ...
  });

  it('should handle <edge case>', async () => {
    ...
  });

  it('should throw <error type> if <condition>', async () => {
    ...
  });
});



4: Debug Test Failures

    "I'm encountering these test failures in my Shopping Cart tests. Help me understand and fix each issue:

    1. TypeError Issue:
    ```
    ERROR: TypeError: Cannot read property 'id' of undefined
    Test: 'should update quantity for existing item'
    Code snippet:
    test('should update quantity for existing item', () => {
    const product = getProduct(1);  // Undefined error here
    cart.addItem(product, 2);
    });

    Current Implementation:
    function getProduct(id) {
    return ProductService.getProduct(id);
    }
    ```

    2. Mock Function Call Count Issue:
    ```
    Error: Received number of calls: 0
    Expected number of calls: 1
    Test: 'should call product service when adding item'
    Code:
    test('should call product service', () => {
    cart.addItem(1, 2);
    expect(ProductService.getProduct).toHaveBeenCalled();
    });
    ```

    3. Async Test Timing Issue:
    ```
    Error: Test timeout - Async callback was not invoked within 5000ms
    Test: 'should apply discount code'
    Code:
    test('should apply discount code', () => {
    cart.applyDiscount('SAVE10');
    expect(cart.total).toBe(90);
    });
    ```

    4. State Persistence Issue:
    ```
    Error: Expected length: 0, Received length: 1
    Test: 'should have empty cart initially'
    Previous test affecting state?
    ```

    For each error:
    1. What's the root cause?
    2. How to fix the implementation?
    3. How to prevent similar issues?
    4. What best practices should be followed?"

5: Comprehensive Mocking Scenarios

    "Need help creating thorough mocks for Shopping Cart's external dependencies:

    1. ProductService Interface:
    ```typescript
    interface ProductService {
    getProduct(id: number): Promise<Product>;
    checkStock(id: number): Promise<boolean>;
    getPrice(id: number): Promise<number>;
    }

    type Product = {
    id: number;
    name: string;
    price: number;
    stock: number;
    category: string;
    }
    ```

    2. UserService Interface:
    ```typescript
    interface UserService {
    getUserById(id: string): Promise<User>;
    getUserPreferences(id: string): Promise<UserPrefs>;
    validateUser(id: string): Promise<boolean>;
    }

    type User = {
    id: string;
    name: string;
    email: string;
    membershipLevel: string;
    }
    ```

    3. DiscountService Interface:
    ```typescript
    interface DiscountService {
    validateCode(code: string): Promise<DiscountInfo>;
    calculateDiscount(total: number, code: string): Promise<number>;
    isUserEligible(userId: string, code: string): Promise<boolean>;
    }

    type DiscountInfo = {
    valid: boolean;
    discountType: 'percentage' | 'fixed';
    value: number;
    minimumPurchase?: number;
    expiryDate?: Date;
    }
    ```

    Test Scenarios Needed:
    1. Happy path with valid data
    2. Network errors and timeouts
    3. Invalid data responses
    4. Conditional responses based on input
    5. Sequential calls with different results

    Requirements:
    1. Mock implementations for all methods
    2. Error scenarios simulation
    3. Async behavior testing
    4. Spy on method calls
    5. Verify call parameters
    6. Handle chained calls
    7. Reset between tests

    How should these mocks be structured for maximum maintainability and test coverage?"
