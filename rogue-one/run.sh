if [ ! -d node_modules ]
then
  echo "==> Installing dependencies..."
  npm install
fi

if [ ! -f /tmp/timestamp ]
then
  date +%s > /tmp/timestamp
  echo "==> Waiting for database startup (30 seconds)"
  sleep 30
else
  echo "==> Waiting for database startup (5 seconds)"
  sleep 5
fi

echo "==> Starting up..."
exec npm run dev
