export default async function handler(req, res) {
  const { orderId } = req.query;
  res.status(200).json({ message: 'Received', orderId });
}
