const fs = require("fs/promises");

const path = require("path");

const crypto = require("crypto");

const contactsPath = path.join(__dirname, "../", "db/contacts.json");

async function readContacts() {
  const data = await fs.readFile(contactsPath, { encoding: "utf-8" });

  return JSON.parse(data);
}
function writeContacts(contacts) {
  return fs.writeFile(contactsPath, JSON.stringify(contacts, undefined, 2));
}

async function listContacts() {
  const contacts = await readContacts();
  return contacts;
}
async function getContactById(id) {
  const contacts = await readContacts();
  const result = contacts.find((contact) => contact.id === id);
  return result || null;
}

async function addContact({ name, email, phone }) {
  const contacts = await readContacts();
  const newContact = { id: crypto.randomUUID(), name, email, phone };

  contacts.push(newContact);
  await writeContacts(contacts);
  return newContact;
}

async function removeContact(id) {
  const contacts = await readContacts();
  const index = contacts.findIndex((contact) => contact.id === id);

  if (index === -1) {
    return null;
  }
  const deletedContact = contacts[index];
  contacts.splice(index, 1);
  await writeContacts(contacts);
  return deletedContact;
}
async function updateByContact(id, body) {
  const contacts = await listContacts();
  const index = contacts.findIndex((contact) => contact.id === id);
  if (index === -1) return null;
  contacts[index] = { ...contacts[index], ...body };
  await writeContacts(contacts);
  return contacts[index];
}

module.exports = {
  listContacts,
  getContactById,
  addContact,
  removeContact,
  updateByContact,
};
