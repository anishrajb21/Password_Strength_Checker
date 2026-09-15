from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from manager import load_data
from crypto import get_fernet


def export_pdf():

    data = load_data()

    if not data:
        print("No data found.")
        return

    fernet = get_fernet()

    pdf = SimpleDocTemplate("passwords.pdf")

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph("Password Vault", styles['Title'])
    )

    elements.append(Spacer(1, 12))

    for platform, users in data.items():

        elements.append(
            Paragraph(
                f"<b>{platform}</b>",
                styles['Heading2']
            )
        )

        elements.append(Spacer(1, 6))

        for username, enc in users.items():

            password = fernet.decrypt(
                enc.encode()
            ).decode()

            text = (
                f"Username: {username}<br/>"
                f"Password: {password}"
            )

            elements.append(
                Paragraph(text, styles['BodyText'])
            )

            elements.append(Spacer(1, 8))

    pdf.build(elements)

    print("PDF Exported Successfully.")