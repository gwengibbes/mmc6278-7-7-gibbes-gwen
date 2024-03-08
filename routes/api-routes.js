require('dotenv').config()
const router = require('express').Router()
const bcrypt = require('bcrypt')
const db = require('../db')
const checkAuth = require('../middleware/auth')

router
  .route('/cart')
  .post(checkAuth, async (req, res) => {
    const {quantity} = req.body
    const {inventoryId} = req.query
    const [[item]] = await db.query(
      `SELECT * FROM inventory WHERE id=?`,
      [inventoryId]
    )
    if (!item) return res.status(404).send('Item not found')
    if (quantity > item.quantity)
      return res.status(409).send('Not enough inventory')

    const [[cartItem]] = await db.query(
      `SELECT
        inventory.id,
        name,
        price,
        inventory.quantity AS inventoryQuantity,
        cart.id AS cartId,
        cart.user_id
      FROM inventory
      LEFT JOIN cart on cart.inventory_id=inventory.id
      WHERE inventory.id=? AND cart.user_id=?;`,
      [inventoryId, req.session.userId]
    )
    if (cartItem) {
      await db.query(
        `UPDATE cart SET quantity=quantity+? WHERE inventory_id=? AND user_id=?`,
        [quantity, inventoryId, req.session.userId]
      )
    } else {
      await db.query(
        `INSERT INTO cart(inventory_id, quantity, user_id) VALUES (?,?,?)`,
        [inventoryId, quantity, req.session.userId]
      )
    }
    res.redirect('/cart')
  })
  .delete(checkAuth, async (req, res) => {
    await db.query('DELETE FROM cart WHERE user_id=?', [req.session.userId])
    res.redirect('/cart')
  })

router
  .route('/cart/:cartId')
  .put(checkAuth, async (req, res) => {
    const {quantity} = req.body
    const [[cartItem]] = await db.query(
      `SELECT
        inventory.quantity as inventoryQuantity
        FROM cart
        LEFT JOIN inventory on cart.inventory_id=inventory.id
        WHERE cart.id=? AND cart.user_id=?`,
        [req.params.cartId, req.session.userId]
    )
    if (!cartItem)
      return res.status(404).send('Not found')
    const {inventoryQuantity} = cartItem
    if (quantity > inventoryQuantity)
      return res.status(409).send('Not enough inventory')
    if (quantity > 0) {
      await db.query(
        `UPDATE cart SET quantity=? WHERE id=? AND user_id=?`
        ,[quantity, req.params.cartId, req.session.userId]
      )
    } else {
      await db.query(
        `DELETE FROM cart WHERE id=? AND user_id=?`,
        [req.params.cartId, req.session.userId]
      )
    }
    res.status(204).end()
  })
  .delete(checkAuth, async (req, res) => {
    const [{affectedRows}] = await db.query(
      `DELETE FROM cart WHERE id=? AND user_id=?`,
      [req.params.cartId, req.session.userId]
    )
    if (affectedRows === 1)
      res.status(204).end()
    else
      res.status(404).send('Cart item not found')
  })

// This route should create a new User
router.post('/user', async (req, res) => {
  const {username, password} = req.body
  // if the username or password is not provided, return a 400 status
  if(!username || !password) {
    return res.status(400).send()
  }
  // hash the password using bcrypt.hash and use 10 salt rounds
  const hashedPassword = bcrypt.hashSync(password, 10);
  // then insert the username and hashed password into the users table
  try {
    await db.query('INSERT INTO users (username, password) VALUE(?, ?)', [username, hashedPassword]);
    // and redirect the user to the /login page
    res.redirect('/login')
  } catch(error){
    // if an error occurs with a code property equal to 'ER_DUP_ENTRY'
    if(error.code === 'ER_DUP_ENTRY'){
      // return a 409 status code (the user exists already)
      return res.status(409).send()
    } else {
      // for any other error, return a 500 status
      return res.status(500).send()
    }
  }
})

// This route will log the user in and create the session
router.post('/login', async (req, res) => {
  const {username, password} = req.body
  // if the username or password is not provided, return a 400 status
  if(!username || !password) {
    return res.status(400).send()
  }
  // Query the database by the username for the user
  const queryResult = await db.query('SELECT * FROM users WHERE username=?', [username]);
  const users = queryResult[0];
  // If no user is found, return a 400 status code
  if(users.length === 0){
    return res.status(400).send();
  }
  const user = users[0];
  // If the user is found, use bcrypt.compare to compare the password to the hash
  const passwordsMatch = bcrypt.compareSync(password, user.password);
  // If the password is wrong, return a 400 status code
  if(passwordsMatch === false){
    return res.status(400).send();
  }
  // If the password matches, set req.session.loggedIn to true
  req.session.loggedIn = true
  // set req.session.userId to the user's id
  req.session.userId = user.id;
  // call req.session.save and in the callback redirect to /
  req.session.save(err=>{
    if(err){
      return res.status(500).send();
    }
    res.redirect('/')
  });
})

router.get('/logout', async (req, res) => {
  // call req.session.destroy and in the callback redirect to /
  req.session.destroy(()=> res.redirect('/'))
})

module.exports = router
