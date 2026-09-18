const { add } = require("../src/calc");

describe("add", () => {
  it("adds", () => {
    expect(add(1, 2)).toBe(3);
  });

  it("runs without checking", () => {
    add(1, 2);
  });

  test("snapshot", () => {
    expect(add(2, 2)).toMatchSnapshot();
    expect(add(3, 3)).toEqual(6);
  });

  it.each([
    [1, 1],
    [2, 2],
  ])("each %i", (a, b) => {
    expect(add(a, 0)).toBe(b);
  });

  test("helper", () => {
    expectSum(1, 2, 3);
  });

  it.todo("later");
});

function expectSum(a, b, total) {
  expect(add(a, b)).toBe(total);
}
