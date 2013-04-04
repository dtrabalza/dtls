package org.spongycastle.asn1.isismtt.x509;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x500.DirectoryString;

/**
 * Some other restriction regarding the usage of this certificate.
 * <p/>
 * <pre>
 *  RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
 * </pre>
 */
public class Restriction extends ASN1Encodable
{
    private DirectoryString restriction;

    public static Restriction getInstance(Object obj)
    {
        if (obj instanceof Restriction)
        {
            return (Restriction)obj;
        }

        if (obj instanceof ASN1String)
        {
            return new Restriction(DirectoryString.getInstance(obj));
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
            + obj.getClass().getName());
    }

    /**
     * Constructor from DERString.
     * <p/>
     * The DERString is of type RestrictionSyntax:
     * <p/>
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * </pre>
     *
     * @param restriction A DERString.
     */
    private Restriction(DirectoryString restriction)
    {
        this.restriction = restriction;
    }

    /**
     * Constructor from a given details.
     *
     * @param restriction The describtion of the restriction.
     */
    public Restriction(String restriction)
    {
        this.restriction = new DirectoryString(restriction);
    }

    public DirectoryString getRestriction()
    {
        return restriction;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p/>
     * Returns:
     * <p/>
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * <p/>
     * </pre>
     *
     * @return a DERObject
     */
    public DERObject toASN1Object()
    {
        return restriction.toASN1Object();
    }
}
