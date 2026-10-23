/**
 * Stockora SaaS — Firebase Cloud Functions (Optional Trusted Backend Component)
 * Provides server-authoritative validation for subscription renewals, payment approvals,
 * and role-based access control.
 */

const functions = require("firebase-functions");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

/**
 * Verify whether the caller has the Super Admin role.
 */
async function verifySuperAdmin(context) {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "User must be authenticated.");
  }
  const uid = context.auth.uid;
  const adminDoc = await db.collection("admins").doc(uid).get();
  if (adminDoc.exists) return true;

  const userDoc = await db.collection("users").doc(uid).get();
  if (userDoc.exists && userDoc.data().role === "superadmin") {
    return true;
  }
  throw new functions.https.HttpsError("permission-denied", "Super Admin privileges required.");
}

/**
 * Server-authoritative payment approval.
 * Prevents client-side manipulation of subscription status.
 */
exports.approvePayment = functions.https.onCall(async (data, context) => {
  await verifySuperAdmin(context);
  const { paymentId, durationDays = 30, adminNotes = "Approved via admin" } = data;

  if (!paymentId) {
    throw new functions.https.HttpsError("invalid-argument", "Payment ID is required.");
  }

  const paymentRef = db.collection("payments").doc(paymentId);
  const paymentDoc = await paymentRef.get();

  if (!paymentDoc.exists) {
    throw new functions.https.HttpsError("not-found", "Payment record not found.");
  }

  const payment = paymentDoc.data();
  if (payment.status === "approved") {
    throw new functions.https.HttpsError("failed-precondition", "Payment is already approved.");
  }

  const shopId = payment.shopId;
  const userRef = db.collection("users").doc(shopId);
  const userDoc = await userRef.get();

  if (!userDoc.exists) {
    throw new functions.https.HttpsError("not-found", "Shop user profile not found.");
  }

  const now = new Date();
  const currentExpiry = userDoc.data().premiumExpiresAt 
    ? new Date(userDoc.data().premiumExpiresAt) 
    : now;
  
  const baseDate = currentExpiry > now ? currentExpiry : now;
  const newExpiry = new Date(baseDate.getTime() + durationDays * 24 * 60 * 60 * 1000);

  const batch = db.batch();

  batch.update(paymentRef, {
    status: "approved",
    reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
    reviewedBy: context.auth.uid,
    adminNotes: adminNotes,
    grantedDays: durationDays
  });

  batch.update(userRef, {
    plan: "premium",
    premiumExpiresAt: newExpiry.toISOString(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  });

  const auditRef = db.collection("auditLogs").doc();
  batch.set(auditRef, {
    actor: context.auth.token.email || context.auth.uid,
    action: "approve_payment",
    targetShopId: shopId,
    targetShopName: payment.shopName || "",
    paymentId: paymentId,
    trxId: payment.trxId || "",
    amount: payment.amount || 0,
    grantedDays: durationDays,
    newExpiry: newExpiry.toISOString(),
    timestamp: admin.firestore.FieldValue.serverTimestamp()
  });

  await batch.commit();
  return { success: true, newExpiry: newExpiry.toISOString() };
});

/**
 * Server-authoritative payment rejection.
 */
exports.rejectPayment = functions.https.onCall(async (data, context) => {
  await verifySuperAdmin(context);
  const { paymentId, reason = "Payment verification failed" } = data;

  if (!paymentId) {
    throw new functions.https.HttpsError("invalid-argument", "Payment ID is required.");
  }

  const paymentRef = db.collection("payments").doc(paymentId);
  const paymentDoc = await paymentRef.get();
  if (!paymentDoc.exists) {
    throw new functions.https.HttpsError("not-found", "Payment record not found.");
  }

  const payment = paymentDoc.data();
  const batch = db.batch();

  batch.update(paymentRef, {
    status: "rejected",
    reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
    reviewedBy: context.auth.uid,
    adminNotes: reason
  });

  const auditRef = db.collection("auditLogs").doc();
  batch.set(auditRef, {
    actor: context.auth.token.email || context.auth.uid,
    action: "reject_payment",
    targetShopId: payment.shopId,
    paymentId: paymentId,
    trxId: payment.trxId || "",
    reason: reason,
    timestamp: admin.firestore.FieldValue.serverTimestamp()
  });

  await batch.commit();
  return { success: true };
});
