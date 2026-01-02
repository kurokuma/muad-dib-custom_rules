// Large file test
const data = [];
for (let i = 0; i < 100000; i++) {
  data.push({ id: i, value: Math.random() });
}
console.log(data.length);