const { expect } = require('chai');

const isValidEmail = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
};

describe('Unit Tests: Validations & Business Rules', () => {
  it('should return true for a valid email format', () => {
    const result = isValidEmail('devops@example.com');
    expect(result).to.be.true;
  });

  it('should return false for an invalid email missing @', () => {
    const result = isValidEmail('invalid-email.com');
    expect(result).to.be.false;
  });

  it('should return false for an empty email string', () => {
    const result = isValidEmail('');
    expect(result).to.be.false;
  });
});