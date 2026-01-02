// Code normal sans menaces
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

// Commentaire mentionnant .npmrc pour test faux positif
// On ne devrait pas detecter: .npmrc, GITHUB_TOKEN, eval