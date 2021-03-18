function myfunction(letter_index)
{
  if(letter_index == 'A'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingOne">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseOne" aria-expanded="false" aria-controls="collapseOne">
            Access Control (AC)
          </a>
        </h4>
      </div>
      <div id="collapseOne" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingOne">
        <div class="panel-body">
        The process of granting or denying specific requests to: <br> <br>
          <li>Obtain and use information and related information processing services;</li><br>
          <li>Enter specific physical facilities (e.g., federal buildings, military establishments, border  crossing entrances</li><br>
          For reference: <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">CMMC Glossary and Acronyms Version 1.10</a>
        </div>
      </div>
    </div>
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwo">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwo" aria-expanded="false" aria-controls="collapseTwo">
            Amazon Web Services (AWS)
          </a>
        </h4>
      </div>
      <div id="collapseTwo" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwo">
        <div class="panel-body">
          Amazon Web Services (AWS) is a cloud services platform, offering compute power, database storage, content delivery and other functionality to help businesses
          scale and grow.
          AWS provides commercial cloud capability across all classification levels: Unclassified, Sensitive, Secret, and Top Secret making it possible to execute
          missions with a common set of tools, a constant flow of the latest technology, and the flexibility to rapidly scale with the mission.
          AWS Cloud infrastructure and services have been validated by third-party testing performed against the NIST 800-53 Revision 4 controls, as well as additional
          FedRAMP requirements. AWS has received FedRAMP Authorizations to Operate (ATO) from multiple authorizing agencies for both AWS GovCloud (US) and the AWS US
          East/West Region. For more information, see the <a href="https://aws.amazon.com/compliance/services-in-scope/" target="_blank">AWS FedRAMP
          compliance webpage</a>, or the following <a href="https://aws.amazon.com/government-education/government/?nc2=h_ql_sol_ind_gov" target="_blank">FedRAMP Marketplace webpages</a>.
        </div>
      </div>
    </div>
    `}
  if (letter_index == 'C') {
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThree">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThree" aria-expanded="false" aria-controls="collapseThree">
            Christian Doctrine
          </a>
        </h4>
      </div>
      <div id="collapseThree" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThree">
        <div class="panel-body">
          The Christian doctrine provides that a mandatory statute or regulation that expresses a significant or deeply ingrained strand of public procurement policy
          shall be read into a federal contract by operation of law, even if the clause is not in the contract. G. L. Christian & Associates v. United States,
          312 F.2d 418 (Ct. Cl. 1963). The doctrine is an exception to the general rule that the government must put vendors on notice of contract requirements,
          whether expressly or through incorporation by reference. It also is an exception to standard commercial contracting practices and contract interpretation
          principles. The rationale for the doctrine is that procurement policies set by higher authority cannot be avoided or evaded (deliberately or negligently)
          by lower government officials. <br>
          <a href="https://governmentcontractsnavigator.com/2018/11/19/what-is-the-christian-doctrine-and-why-should-you-care/" target="_blank">Reference</a>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFour">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFour" aria-expanded="false" aria-controls="collapseFour">
            CMMC Third-Party Assessment Organization (C3PAO)
          </a>
        </h4>
      </div>
      <div id="collapseFour" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFour">
        <div class="panel-body">
           A C3PAO or CPAO is a licensed organization (licensed by the CMMC-AB) that can deliver a certified CMMC assessment via contractual agreement.
           The assessment will be conducted by a Certified Assessor (CA) or an Authorized Provisional Assessor (APA) that is either a contractor or an
           employee under a written agreement.<br>
           References: <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">CMMC Assessment Guide Level 1  Version 1.10</a> and
           <a href="https://info.summit7systems.com/blog/cmmc" target="_blank">What is the Cybersecurity Maturity Model Certification (CMMC)?</a>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFive">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFive" aria-expanded="false" aria-controls="collapseFive">
            Common Vulnerabilities and Exposure (CVE)
          </a>
        </h4>
      </div>
      <div id="collapseFive" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFive">
        <div class="panel-body">
          Common Vulnerabilities and Exposure is a list of records—each containing an identification number, a
          description, and at least one public reference—for publicly known cybersecurity vulnerabilities. References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Assessment Guide </a> and
          <a href="http://cve.mitre.org/" target="_blank"> Definition Source </a>
          <br>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingSix">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseSix" aria-expanded="false" aria-controls="collapseSix">
            Common Weakness Enumeration (CWE)
          </a>
        </h4>
      </div>
      <div id="collapseSix" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingSix">
        <div class="panel-body">
        Common Weakness Enumeration is a community-developed list of software and hardware weakness types. It serves as a common language, a measuring stick for security tools,
        and as a baseline for weakness identification, mitigation, and prevention efforts. References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Assessment Guide </a> and
          <a href="http://cwe.mitre.org/" target="_blank"> Definition Source </a>
          <br>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingSeven">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseSeven" aria-expanded="false" aria-controls="collapseSeven">
          Compact Disc Read-Only Memory (CD-ROM)
          </a>
        </h4>
      </div>
      <div id="collapseSeven" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingSeven">
        <div class="panel-body">
        A Compact Disc(CD)is a class of media from which data are read by optical means. CUI can be stored and transported on a variety of media like magnetic disks, tapes, USB drives, CD-ROMs, and so on.
        This makes digital CUI data very portable. The portability increases the chance that the media is lost. When identifying the paths CUI flows through your organization, identify devices to include
        in this practice.
        To mitigate the risk of losing or exposing CUI an organization should implement an encryption scheme to protect the data. Even if the media is lost the fact that it is properly encrypted renders
        the data inaccessible to other people. When encryption is not an option, alternative physical safeguards should be applied during transport. <br>
        References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Assessment Guide </a>,
          <a href="https://csrc.nist.gov/glossary/term/CD" target="_blank"> NIST Glossary </a> and
          <a href="https://ndisac.org/dibscc/cyberassist/cybersecurity-maturity-model-certification/level-3/mp-3-125/" target="_blank"> CMMC Practice </a>
          <br>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingEighth">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseEighth" aria-expanded="false" aria-controls="collapseEighth">
          Computerized Numerical Control (CNC)
          </a>
        </h4>
      </div>
      <div id="collapseEighth" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingEighth">
        <div class="panel-body">
        CNC machining can be explained as a production method that is used by different industries, such as, aerospace, construction, agriculture, and automotive. It helps in the manufacturing of a wide
        array of products which are the surgical equipment, garden tools, frames of automobiles, and airplane engines.
        The method involves many different computer-operated machine operations that include the chemical, mechanical, thermal, and electrical processes. References
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Assessment Guide </a> and
          <a href="https://www.cnc.com/computer-numerical-control/" target="_blank"> CNC.com </a>

          <br>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingNine">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseNine" aria-expanded="false" aria-controls="collapseNine">
          Controlled Unclassified Information (CUI)
          </a>
        </h4>
      </div>
      <div id="collapseNine" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingNine">
        <div class="panel-body">
        Information that requires safeguarding or dissemination controls pursuant to and consistent  with law, regulations, and government-wide policies, excluding information that is classified  under
        Executive Order 13526, Classified National Security Information, December 29, 2009,  or any predecessor or successor order, or the Atomic Energy Act of 1954, as amended. References:
        <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Assessment Guide </a>
        <br>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTen" aria-expanded="false" aria-controls="collapseTen">
          Covered Defense Information (CDI)
          </a>
        </h4>
      </div>
      <div id="collapseTen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTen">
        <div class="panel-body">
        A term used to identify information that requires protection under DFARS Clause 252.204- 7012. Unclassified controlled technical information (CTI) or other information, as described  in the CUI
        Registry, that requires safeguarding or dissemination controls pursuant to and  consistent with law, regulations, and Government wide policies and is:
        <li>Marked or otherwise identified in the contract, task order, or delivery order and provided  to contractor by or on behalf of, DoD in support of the performance of the contract; OR</li>
        <li>Collected, developed, received, transmitted, used, or stored by—or on behalf of—the  contractor in support of the performance of the contract. </li>
        References:
        <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Glossary and Acronyms </a>
        <br>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingEleven">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseEleven" aria-expanded="false" aria-controls="collapseEleven">
          Cybersecurity Maturity Model Certification (CMMC)
          </a>
        </h4>
      </div>
      <div id="collapseEleven" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingEleven">
        <div class="panel-body">
        A framework that combines various cybersecurity standards and best practices and maps  those controls and processes across several maturity levels that range from basic to  advanced cyber hygiene,
        and that, when implemented, will reduce risk against a specific set  of cyber threats.  <br>
        DoD is issuing an interim rule to amend the Defense Federal Acquisition Regulation Supplement (DFARS) to implement a DoD Assessment Methodology and Cybersecurity Maturity Model Certification
        framework in order to assess contractor implementation of cybersecurity requirements and enhance the protection of unclassified information within the DoD supply chain. <br>
        References:
        <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank"> CMMC Glossary and Acronyms </a> and
        <a href="https://www.federalregister.gov/documents/2020/09/29/2020-21123/defense-federal-acquisition-regulation-supplement-assessing-contractor-implementation-of" target="_blank">
        Federal Register </a>
        <br>
        </div>
      </div>
    </div>
    `

  }
  if (letter_index == 'D'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwelve">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwelve" aria-expanded="false" aria-controls="collapseTwelve">
            Data loss prevention (DLP)

          </a>
        </h4>
      </div>
      <div id="collapseTwelve" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwelve">
        <div class="panel-body">
        Data loss prevention (DLP) is a set of tools and processes used to ensure that sensitive data is not lost, misused, or accessed by unauthorized users.
        DLP also provides reporting to meet compliance and auditing requirements and identify areas of weakness and anomalies for forensics and incident response. Reference:
          <a href="https://digitalguardian.com/blog/what-data-loss-prevention-dlp-definition-data-loss-prevention#:~:text=Data%20loss%20prevention%20(DLP)%20is,or%20accessed%20by%20unauthorized%20users.&text=DLP%20also%20provides%20reporting%20to,for%20forensics%20and%20incident%20response." target="_blank">
            What is data loss?</a>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirteen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirteen" aria-expanded="false" aria-controls="collapseThirteen">
            Defense Contract Management Agency (DCMA)
          </a>
        </h4>
      </div>
      <div id="collapseThirteen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirteen">
        <div class="panel-body">
          The Defense Contract Management Agency is, first and foremost, a product delivery organization. Our nation’s warfighters expect our defense industry to produce and deliver the equipment they need to
          fight, survive and win. DCMA’s integrated team of acquisition and support professionals makes this happen. <br>
          The Agency provides contract administration services for the Department of Defense, other federal organizations and international partners, and is an essential part of the acquisition process from
          pre-award to sustainment. Around 12,000 employees, mostly civilians, work at offices and contractor facilities around the world, divided among three continental U.S. commands, one international command
          and other specialized offices. <br>
          Together, the Agency manages 300,000 contracts, valued at more than $7 trillion, at 15,000 contractor locations worldwide. DCMA makes sure DoD, other federal agencies, and partner nation customers get
          the equipment they need, delivered on time, at projected cost, and meeting all performance requirements. <br>
          Every business day, DCMA receives nearly 1,000 new contracts and authorizes more than $700 million in payments to contractors. Most importantly, every day our team delivers more than a million and a
          half items – from fighter jets to fasteners – to our warfighters.
          <a href="https://www.dcma.mil/About-Us/"> About DCMA</a>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFourteen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFourteen" aria-expanded="false" aria-controls="collapseFourteen">
            Defense Federal Acquisition Regulation System (DFARS)
          </a>
        </h4>
      </div>
      <div id="collapseFourteen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFourteen">
        <div class="panel-body">
          The Defense Federal Acquisition Regulation Supplement (DFARS) to the Federal Acquisition Regulation (FAR) is administered by the Department of Defense (DoD). The Federal Acquisition Regulation (FAR)
          is the principal set of rules in the Federal Acquisition Regulations System regarding government procurement in the United States, and is codified at Chapter 1 of Title 48 of the Code of Federal
          Regulations, 48 C.F.R. The DFARS implements and supplements the FAR. The DFARS contains requirements of law, DoD-wide policies, delegations of FAR authorities, deviations from FAR requirements, and
          policies/procedures that have a significant effect on the public. The DFARS should be read in conjunction with the primary set of rules in the FAR. See also the suggested search for Government
          Contracts.
          <a href="https://www.acq.osd.mil/cmmc/draft.html">CMMC Assessment Guide</a>.
          <a href="https://www.plianced.com/compliance-wiki/how-to-be-dfars-compliant-procedures-guidance-and-information/">How to be DFARS Compliant</a>.
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFifteen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFifteen" aria-expanded="false" aria-controls="collapseFifteen">
            Defense Industrial Base Cybersecurity Assessment Center (DIBCAC)
          </a>
        </h4>
      </div>
      <div id="collapseFifteen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFifteen">
        <div class="panel-body">
          The Defense Contract Management Agency’s Defense Industrial Base Cybersecurity Assessment Center, or DIBCAC, partnered with Project Spectrum in early May to inform small businesses on their
          responsibility for information protection. Supported by the Defense Department’s Office of Small Business Programs, Project Spectrum provides resources and training to help improve cyber-readiness and
          compliance. <br>
          DIBCAC looks closely at contractor and supplier information protection systems to provide their findings to DoD organizations so they can make informed decisions when entering contracts.
          Reference:
          <a href="https://www.dcma.mil/News/Article-View/Article/2194518/agency-provides-big-cybersecurity-support-to-small-business/">Agency provides big cybersecurity support to small business</a>.
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingSixteen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseSixteen" aria-expanded="false" aria-controls="collapseSixteen">
            Defense Industrialized Base (DIB)
          </a>
        </h4>
      </div>
      <div id="collapseSixteen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingSixteen">
        <div class="panel-body">
          The worldwide industrial complex that enables research and development, as well as design,  production, delivery, and maintenance of military weapons systems, subsystems, and  components or parts,
           to meet U.S. military requirements.
        <a href="https://www.acq.osd.mil/cmmc/draft.html">CMMC Assessment Guide</a>.
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingSeventeen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseSeventeen" aria-expanded="false" aria-controls="collapseSeventeen">
             Demilitarized Zone (DMZ)
          </a>
        </h4>
      </div>
      <div id="collapseSeventeen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingSeventeen">
        <div class="panel-body">
          A perimeter network segment that is logically between internal and external networks. Its  purpose is to enforce the internal network’s Information Assurance (IA) policy for external
          information exchange and to provide external, untrusted sources with restricted access to  releasable information while shielding the internal networks from outside attacks.
        <a href="https://www.acq.osd.mil/cmmc/draft.html">CMMC Glossary and Acronyms Version</a>.
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingEighteen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseEighteen" aria-expanded="false" aria-controls="collapseEighteen">
             Department of Defense (DoD)
          </a>
        </h4>
      </div>
      <div id="collapseEighteen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingEighteen">
        <div class="panel-body">
          The United States Department of Defense (DoD, USDOD or DOD) is an executive branch department of the federal government charged with coordinating and supervising all agencies and functions of the
          government directly related to national security and the United States Armed Forces.
        <a href="https://www.acq.osd.mil/cmmc/draft.html">CMMC Assessment Guide</a>.
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingNineteen">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseNineteen" aria-expanded="false" aria-controls="collapseNineteen">
             Distributed Denial of Service (DDOS)
          </a>
        </h4>
      </div>
      <div id="collapseNineteen" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingNineteen">
        <div class="panel-body">
          A denial of service technique that uses numerous hosts to perform the attack. DDoS is a cyber-attack that cripples the victim’s site, resulting in temporary or permanent damage to the site.
          The way this works is that the attacker will flood a website with unwanted traffic from multiple devices, rendering the website of no use to anyone. The attacker aims for a DDoS attack to be
          successful in the first attempt.

        <a href="https://csrc.nist.gov/glossary/term/DDoS">NIST.gov</a> and
        <a href="https://www.purevpn.com/ddos/what-happens-during-a-ddos-attack#:~:text=DDoS%20is%20a%20cyber-attack%20that%20cripples%20the%20victim%E2%80%99s,attack%20to%20be%20successful%20in%20the%20first%20attempt.">What happens during a DDoS attack?</a>.
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwenty">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwenty" aria-expanded="false" aria-controls="collapseTwenty">
            Domain Name Systems (DNS)
          </a>
        </h4>
      </div>
      <div id="collapseTwenty" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwenty">
        <div class="panel-body">
          The Domain Name System (DNS) is the phonebook of the Internet. Humans access information online through domain names, like nytimes.com or espn.com. Web browsers interact through Internet Protocol (IP)
          addresses. DNS translates domain names to IP addresses so browsers can load Internet resources. <br>
          Each device connected to the Internet has a unique IP address which other machines use to find the device. DNS servers eliminate the need for humans to memorize IP addresses such as 192.168.1.1
          (in IPv4), or more complex newer alphanumeric IP addresses such as 2400:cb00:2048:1::c629:d7a2 (in IPv6) <br>
        <a href="https://www.cloudflare.com/learning/dns/what-is-dns/">What is DNS?</a> and
          <a href="https://cyber.dhs.gov/ed/19-01/">Extra Info</a>
        </div>
      </div>
    </div>


    `
  }
  if (letter_index == 'E'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyOne">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyOne" aria-expanded="false" aria-controls="collapseTwentyOne">
            Encryption at rest
          </a>
        </h4>
      </div>
      <div id="collapseTwentyOne" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyOne">
        <div class="panel-body">
          Encryption is the secure encoding of data used to protect confidentiality of data. <br>
          Encryption at rest provides data protection for stored data (at rest). Attacks against data at-rest include attempts to obtain physical access to the hardware on which the data is stored, and then
          compromise the contained data. In such an attack, a server's hard drive may have been mishandled during maintenance allowing an attacker to remove the hard drive. Later the attacker would put the hard
          drive into a computer under their control to attempt to access the data. <br>
          Encryption at rest is designed to prevent the attacker from accessing the unencrypted data by ensuring the data is encrypted when on disk. If an attacker obtains a hard drive with encrypted data but
          not the encryption keys, the attacker must defeat the encryption to read the data. This attack is much more complex and resource consuming than accessing unencrypted data on a hard drive.
          For this reason, encryption at rest is highly recommended and is a high priority requirement for many organizations. <br>
          Reference:


        <a href="https://docs.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest#:~:text=Encryption%20at%20rest%20is%20designed,encryption%20to%20read%20the%20data.">
           Azure: Data encryption at rest</a>
        </div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyTwo">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyTwo" aria-expanded="false" aria-controls="collapseTwentyTwo">
            Encryption in motion
          </a>
        </h4>
      </div>
      <div id="collapseTwentyTwo" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyTwo">
        <div class="panel-body">
          Encryption is the secure encoding of data in motion used to protect confidentiality of data. <br>
          Data in motion includes the following scenarios: data moving from an Internet-capable endpoint device to a web-facing service in the cloud; data moving between virtual machines within and between cloud
          services and data that is traversing trusted private networks and an untrusted network such as the Internet. <br>
          Perhaps the best-known use of cryptography for the data in transit scenario is secure sockets layer (SSL) and transport layer security (TLS). TLS provides a transport layer -- encrypted "tunnel" between
          email servers or message transfer agents (MTAs), whereas SSL certificates encrypt private communications over the Internet using private and public keys. The ongoing management and responsibility of
          data in transit resides in the correct application of security controls, including the relevant cryptography processes to handle encryption key management. <br>
          Cryptographic protocols have been in use for many years in the form of hypertext transfer protocol secure (HTTPS), typically to provide communication security over the Internet, but it has now become
          the standard encryption approach for browser-to-web host and host-to-host communications in both cloud and non-cloud environments.
          <br>Reference:

        <a href="https://whatis.techtarget.com/definition/data-in-motion#:~:text=Encrypting%20data%20in%20motion&text=TLS%20provides%20a%20transport%20layer,using%20private%20and%20public%20keys.">
           What is data in motion?</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyThree">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyThree" aria-expanded="false" aria-controls="collapseTwentyThree">
            External Service Provider (ESP)

          </a>
        </h4>
      </div>
      <div id="collapseTwentyThree" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyThree">
        <div class="panel-body">
          A provider of external system services to an organization through a variety of consumer-producer relationships including but not limited to: joint ventures; business partnerships; outsourcing
          arrangements (i.e., through contracts, interagency agreements, lines of business arrangements); licensing agreements; and/or supply chain exchanges
          <br>References:

        <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r1.pdf">
           NIST.gov</a> and
        <a href="https://www.acq.osd.mil/cmmc/draft.html">
          CMMC Assessment Guide</a>
        </div>
      </div>
    </div>



    `
  }
  if (letter_index == 'F'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyFour">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyFour" aria-expanded="false" aria-controls="collapseTwentyFour">
            False Claims Act (FCA)

          </a>
        </h4>
      </div>
      <div id="collapseTwentyFour" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyFour">
        <div class="panel-body">
          FCA was enacted in 1963 provides that any person who knowingly submitted false claims to the government was liable for double the government’s damages plus a penalty. <br>
          Brought up sometime in 2020 by Chief Information Security Officer Katie Arrington in response to pushback received from defense contractors about the undue burden of CMMC compliance. <br>
          The aim of the CMMC is not to reinvent the wheel. Instead, the process is intended to standardize, confirm, and certify the Defense Industrial Base companies’ existing self-attestation claims of
          compliance with the various DFARS clauses and NIST regulations. <br>
          If  a defense contractor finds CMMC compliance to be a  significant burden to implement procedures and protections, then the contractor has likely falsified self-attestations and was in violation of
          the FCA in previous contracts. <br>

          <br>References:

        <a href="https://www.safelogic.com/cmmc-and-the-false-claims-act/#:~:text=From%20the%20Department%20of%20Justice,%242%2C000%20for%20each%20false%20claim." target="_blank">
           CMMC and the False Claim Acts</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyFive">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyFive" aria-expanded="false" aria-controls="collapseTwentyFive">
             Federal Acquisition Regulation (FAR)
          </a>
        </h4>
      </div>
      <div id="collapseTwentyFive" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyFive">
        <div class="panel-body">
          The Department of Defense (DoD), GSA, and the National Aeronautics and Space Administration (NASA) jointly issue the Federal Acquisition Regulation (FAR) for use by executive agencies in acquiring goods
          and services. <br>
          The FAR System governs the “acquisition process” by which executive agencies of the United States federal government acquire (i.e., purchase or lease) goods and services by contract with appropriated
          funds.


          <br>References:

        <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
           CMMC Assessment Guide Level</a> and
        <a href="https://www.plianced.com/compliance-wiki/how-to-be-dfars-compliant-procedures-guidance-and-information/" target="_blank">
            How to be DFARS Compliant</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentySix">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentySix" aria-expanded="false" aria-controls="collapseTwentySix">
            Federal Acquisition Regulations System (FARS)

          </a>
        </h4>
      </div>
      <div id="collapseTwentySix" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentySix">
        <div class="panel-body">
          The Federal Acquisition Regulations System is established for the codification and publication of uniform policies and procedures for acquisition by all executive agencies. <br>
          The Federal Acquisition Regulations System consists of the Federal Acquisition Regulation (FAR), which is the primary document, and agency acquisition regulations that implement or supplement the FAR.
          The FAR System does not include internal agency guidance of the type described in 1.301(a)(2).

          <br>References:

        <a href="https://www.acquisition.gov/far/1.101" target="_blank">
           Acquisition.gov</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentySeven">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentySeven" aria-expanded="false" aria-controls="collapseTwentySeven">
            Federal Contract Information (FCI)

          </a>
        </h4>
      </div>
      <div id="collapseTwentySeven" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentySeven">
        <div class="panel-body">
          Federal contract information means information, not intended for public release, that is  provided by or generated for the Government under a contract to develop or deliver a  product or service to the
           Government, but not including information provided by the  Government to the public (such as on public websites) or simple transactional information,  such as necessary to process payments.
          <br>References:

          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
             CMMC Glossary and Acronyms</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyEighth">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyEighth" aria-expanded="false" aria-controls="collapseTwentyEighth">
          Federal Information Processing Standards (FIPS)

          </a>
        </h4>
      </div>
      <div id="collapseTwentyEighth" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyEighth">
        <div class="panel-body">
        FIPS are standards and guidelines for federal computer systems that are developed by the National Institute of Standards and Technology (NIST) in accordance with the Federal Information Security
        Management Act (FISMA) and approved by the Secretary of Commerce. These standards and guidelines are developed when there are no acceptable industry standards or solutions for a particular government
        requirement. Although FIPS are developed for use by the federal government, many in the private sector voluntarily use these standards.
          <br>References:

          <a href="https://www.nist.gov/standardsgov/compliance-faqs-federal-information-processing-standards-fips" target="_blank">
             NIST.gov</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingTwentyNine">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseTwentyNine" aria-expanded="false" aria-controls="collapseTwentyNine">
            Federal Information Security Modernization Act (FISMA)
          </a>
        </h4>
      </div>
      <div id="collapseTwentyNine" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingTwentyNine">
        <div class="panel-body">
          The Federal Information Security Modernization Act [FISMA] of 2014 requires federal agencies to identify and provide information security protections commensurate with the risk resulting from the
          unauthorized access, use, disclosure, disruption, modification, or destruction of information collected or maintained by or on behalf of an agency; or information systems used or operated by an agency
          or by a contractor of an agency or other organization on behalf of an agency.
          <br>References:

          <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r2.pdf" target="_blank">
            Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyOne">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyOne" aria-expanded="false" aria-controls="collapseThirtyOne">
            Federal Risk and Authorization Management Program (FedRAMP)
          </a>
        </h4>
      </div>
      <div id="collapseThirtyOne" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyOne">
        <div class="panel-body">
          The Federal Risk and Authorization Management Program (FedRAMP) is a government-wide program that provides a standardized approach to security assessment, authorization, and continuous monitoring for
          cloud products and services. FedRAMP empowers agencies to use modern cloud technologies, with emphasis on security and protection of federal information, and helps accelerate the adoption of secure,
          cloud solutions.
          <br>References:

          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
             CMMC Assessment Guide</a> and
          <a href="https://www.gsa.gov/technology/government-it-initiatives/fedramp" target="_blank">
          GSA.gov</a>
        </div>
      </div>
    </div>


  `
  }
  if (letter_index == 'G'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyOne">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyOne" aria-expanded="false" aria-controls="collapseThirtyOne">
            gcc-high
          </a>
        </h4>
      </div>
      <div id="collapseThirtyOne" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyOne">
        <div class="panel-body">
          Office 365 GCC High is built on Microsoft Azure Government within 8 dedicated US-sovereign data centers. Azure Government is currently certified to FedRAMP High, and the entire suite of GCC High
          services is undergoing audits to upgrade its certification to FedRAMP High. For many entities interested in GCC High, the foundation of Azure Government is especially helpful because each Microsoft
          employee working those environments is a US Citizen and background checked. This factor is particularly important for companies handling ITAR data.
          <br>References:

          <a href="https://info.summit7systems.com/what-is-microsoft-365-gcc-high" target="_blank">
          What is Office 365 GCC High?</a>
        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'H'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyTwo">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyTwo" aria-expanded="false" aria-controls="collapseThirtyTwo">
            HyperText Transfer Protocol Secure (HTTPS)

          </a>
        </h4>
      </div>
      <div id="collapseThirtyTwo" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyTwo">
        <div class="panel-body">
          It’s a protocol that allows communication between different systems. Most commonly, it is used for transferring data from a web server toa browser to view web pages.
          Highly secure as the data is encrypted before it is seen across a network. <br>
          It allows secure transactions by encrypting the entire communication with SSL. It is a combination of SSL/TLS protocol and HTTP. It provides encrypted and secure identification of a network server. <br>
          HTTP also allows you to create a secure encrypted connection between the server and the browser. It offers the bi-directional security of Data. This helps you to protect potentially sensitive
          information from being stolen. <br>
          HTTP transfers data in plain text while HTTPS transfers data in cipher text (encrypt text).

          <br>References:

          <a href="https://www.guru99.com/difference-http-vs-https.html" target="_blank">
            HTTP vs HTTPS. What is the difference?</a>
        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'I'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyThree">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyThree" aria-expanded="false" aria-controls="collapseThirtyThree">
            Identification (ID)
          </a>
        </h4>
      </div>
      <div id="collapseThirtyThree" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyThree">
        <div class="panel-body">
          Identification is the means by which a user provides a claimed identity to the system. The most common form of identification is the user ID. The following should be considered when using user IDs: <br><br>
          <li>unique identification</li>
          <li>correlate actions to users </li>
          <li>maintenance of user IDs</li>
          <li>active user IDs</li>

          <br>References:

          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a>
          <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-14.pdf" target="_blank">
              NIST.gov</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyFour">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyFour" aria-expanded="false" aria-controls="collapseThirtyFour">
          Industrial Control System (ICS)
          </a>
        </h4>
      </div>
      <div id="collapseThirtyFour" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyFour">
        <div class="panel-body">
          An information system used to control industrial processes such as manufacturing, product handling, production, and distribution or to control infrastructure assets.
          <br>References:
          <a href="https://niccs.cisa.gov/about-niccs/cybersecurity-glossary#S" target="_blank">
              niccs.cisa.gov</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyFive">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyFive" aria-expanded="false" aria-controls="collapseThirtyFive">
            Industrial Internet of Things  (IIoT or I-IoT)
          </a>
        </h4>
      </div>
      <div id="collapseThirtyFive" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyFive">
        <div class="panel-body">
          IIoT leverages many of the same technologies as IoT and applies them to the complex needs of industrial environments. IIoT is a group of technologies that collect and transmit data within traditionally
          isolated industrial devices found in  Supervisory Control and Data Acquisition (SCADA) systems and other Industrial Control Systems (ICS) that monitor and control industrial critical infrastructure
          that includes factories, power plants, water systems, ports, and other industrial facilities as well as certain U.S. and allied military systems.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://www.dhs.gov/sites/default/files/publications/ia/ia_iiot-intercommections.pdf" target="_blank">
              The Industrial Internet of Things</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtySix">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtySix" aria-expanded="false" aria-controls="collapseThirtytSix">
            Information Technology (IT)

          </a>
        </h4>
      </div>
      <div id="collapseThirtySix" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtySix">
        <div class="panel-body">
          Any equipment or interconnected system or subsystem of equipment that processes, transmits, receives, or interchanges data or information.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://niccs.cisa.gov/about-niccs/cybersecurity-glossary#S" target="_blank">
              niccs.cisa.gov</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtySeven">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtySeven" aria-expanded="false" aria-controls="collapseThirtytSeven">
          International Organization for Standardization (ISO)
          </a>
        </h4>
      </div>
      <div id="collapseThirtySeven" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtySeven">
        <div class="panel-body">
          ISO is an independent, non-governmental international organization with a membership of 165 national standards bodies. <br>
          Through its members, it brings together experts to share knowledge and develop voluntary, consensus-based, market relevant International Standards that support innovation and provide solutions to
          global challenges.
          <br>References:
          <a href="https://www.iso.org/about-us.html" target="_blank">
              About ISO</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyEighth">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyEighth" aria-expanded="false" aria-controls="collapseThirtytEighth">
            International Traffic in Arms Regulation (ITAR)
          </a>
        </h4>
      </div>
      <div id="collapseThirtyEighth" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyEighth">
        <div class="panel-body">
          The International Traffic in Arms Regulation (ITAR) controls the export and import of defense-related articles and services on the United States Munitions List (USML). The USML is a list of articles, services, and related technology designated as defense and space related by the United States federal government. Any article, service, or related data found to be on the USML requires an export license issued by the United States State Department to be exported. There are twenty-one categories of articles on the USML and include everything from firearms and other weapons to toxicological and biological agents and technical data.
          ITAR data is a subset of Controlled Unclassified Information (CUI). This means that the baseline protections you are required to provide for CUI-Basic also apply to ITAR.
          <br>References:
          <a href="https://info.summit7systems.com/itar" target="_blank">
              ITAR Compliance in Office 365</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingThirtyNine">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseThirtyNine" aria-expanded="false" aria-controls="collapseThirtytNine">
            Internet of Things (IoT)
          </a>
        </h4>
      </div>
      <div id="collapseThirtyNine" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingThirtyNine">
        <div class="panel-body">
          Internet-ready devices that do not fit the standard definitions of information technology (IT) devices that have been used as the basis for defining device cybersecurity capabilities
           (e.g., smartphones, servers, laptops). <br>
          The IoT devices in scope for this publication have at least one transducer (sensor or actuator) for interacting directly with the physical world and at least one network interface
          (e.g., Ethernet, Wi-Fi, Bluetooth, LongTerm Evolution [LTE], Zigbee, Ultra-Wideband [UWB]) for interfacing with the digital world. <br>
          The IoT devices can function on their own although they may be dependent on specific other devices (e.g., an IoT hub) or systems (e.g., a cloud) for some functionality. <br>
          Many IoT devices have computing functionality, data storage, and network connectivity along with functionality associated with equipment that previously lacked these computing functions
          (e.g., smart appliances). In turn, these functions enable new efficiencies and technological capabilities for the equipment, such as remote access for monitoring, configuration, and troubleshooting. <br>
          IoT can also enable the collection and analysis of data about the physical world and use the results to better inform decision making, alter the physical environment, and anticipate future events .
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a>
          <a href="https://www.nist.gov/programs-projects/nist-cybersecurity-iot-program" target="_blank">
              NIST.gov</a>

        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'L'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingForty">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseForty" aria-expanded="false" aria-controls="collapseForty">
            Local Area Network (LAN)

          </a>
        </h4>
      </div>
      <div id="collapseForty" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingForty">
        <div class="panel-body">
          A LAN is a local networkork and a communications network that is confined to a building or building complex. <br>
          The "clients" in a LAN are the user's computers running Windows, Mac or Linux, while the "servers" hold programs and data shared by the clients. Servers come in a wide range of sizes from PCs to mainframes
          (see server). The Internet hosts millions of them. <br>
          Data transfer over a LAN is managed by the TCP/IP transport protocol, and the physical transmission by cable is Ethernet. Mobile devices are connected by Wi-Fi, Ethernet's wireless counterpart.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a>
          <a href="https://www.pcmag.com/encyclopedia/term/lan" target="_blank">
              Definition of LAN</a>

        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'M'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyOne">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyOne" aria-expanded="false" aria-controls="collapseFortyOne">
            Manufacturing Extension Partnership  (MEP)

          </a>
        </h4>
      </div>
      <div id="collapseFortyOne" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyOne">
        <div class="panel-body">
          NIST MEP is a public-private partnership with Centers in all 50 states and Puerto Rico dedicated to serving small and medium-sized manufacturers. <br>
          The MEP National Network's strength is in its partnerships. Through its collaborations at the federal, state and local level, MEP Centers work with manufacturers to develop new products and customers,
          expand and diversify markets, adopt new technology, and enhance value within supply chains. The MEP Program serves as a bridge to other organizations and federal research labs that share a passion for
          enhancing the manufacturing community.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://www.nist.gov/mep/about-nist-mep" target="_blank">
              NIST.gov</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyTwo">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyTwo" aria-expanded="false" aria-controls="collapseFortyTwo">
            Multi Factor authentication (MFA)
          </a>
        </h4>
      </div>
      <div id="collapseFortyTwo" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyTwo">
        <div class="panel-body">
          MFA requires two or more different factors to achieve authentication. The factors include: <br>
          <li>something you know (e.g. password/PIN); </li>
          <li>something you have (e..g cryptographic identification device, token); </li>
          <li>or something you are (e.g. biometric). </li>
          The MFA requirement should not be interpreted as requiring federal Personal Identity Verification (PIV) card or DoD Common Access Card (CAC)-like solutions.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Glossary and Acronyms</a>
          <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r1.pdf" target="_blank">
              NIST.gov</a>

        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'N'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyThree">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyThree" aria-expanded="false" aria-controls="collapseFortyThree">
            National Institute of Standards and Technology (NIST)
          </a>
        </h4>
      </div>
      <div id="collapseFortyThree" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyThree">
        <div class="panel-body">
        Founded in 1901, NIST is a non-regulatory federal agency within the U.S. Department of Commerce. NIST's mission is to promote U.S. innovation and industrial competitiveness by advancing measurement
        science, standards, and technology in ways that enhance economic security and improve our quality of life.
          <br>References:
          <a href="https://www.nist.gov/director/pao/nist-general-information" target="_blank">
              NIST.gov</a>

        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'O'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyFour">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyFour" aria-expanded="false" aria-controls="collapseFortyFour">
            Open Authorization (OATH)
          </a>
        </h4>
      </div>
      <div id="collapseFortyFour" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyFour">
        <div class="panel-body">
        An open protocol to allow secure authorization in a simple and standard method from web, mobile and desktop applications. It does not deal with authentication, the process of identifying an individual.
          <br>References:
          <a href="https://dzone.com/articles/saml-versus-oauth-which-one#:~:text=SAML%20%28Security%20Assertion%20Markup%20Language%29%20is%20an%20umbrella,of%20resources.%20It%20does%20not%20deal%20with%20authentication." target="_blank">
              SAML vs OATH. Which one should I use?</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyFive">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyFive" aria-expanded="false" aria-controls="collapseFortyFive">
            Operational Technology (OT)

          </a>
        </h4>
      </div>
      <div id="collapseFortyFive" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyFive">
        <div class="panel-body">
          Operational Technology (OT) is hardware and software that detects or causes a change through the direct monitoring and/or control of physical devices, processes and events in the enterprise, according
          to Gartner. OT is common in Industrial Control Systems (ICS) such as a SCADA System. <br>
          In the world of critical infrastructure, OT may be used to control power stations or public transportation. As this technology advances and converges with networked tech the need for OT security grows
          exponentially. <br>
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://www.forcepoint.com/cyber-edu/ot-operational-technology-security#:~:text=Operational%20Technology%20%28OT%29%20is%20hardware%20and%20software%20that,Control%20Systems%20%28ICS%29%20such%20as%20a%20SCADA%20System." target="_blank">
              OT Security</a>

        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'P'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortySix">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortySix" aria-expanded="false" aria-controls="collapseFortySix">
            Personal Identity Verification (PIV)
          </a>
        </h4>
      </div>
      <div id="collapseFortySix" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortySix">
        <div class="panel-body">
          A Personal Identity Verification (PIV) credential is a US Federal governmentwide credential used to access Federally controlled facilities and information systems at the appropriate security level.<br>
          PIV credentials have certificates and key pairs, pin numbers, biometrics like fingerprints and pictures, and other unique identifiers. When put together into a PIV credential, it provides the capability
          to implement multi-factor authentication for networks, applications and buildings. <br>
          Enabling systems and facilities to use PIV credentials for authentication enhances agency security. PIV credentials allow for a high level of assurance in the individuals that access your resources,
          because they are only issued by trusted providers to individuals that have been verified in person. PIV credentials are highly resistant to identity fraud, tampering, counterfeiting, and exploitation.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://piv.idmanagement.gov/" target="_blank">
              PIV Introduction</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortySeven">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortySeven" aria-expanded="false" aria-controls="collapseFortySeven">
            Procurement Integrated Enterprise Environment (PIEE)
          </a>
        </h4>
      </div>
      <div id="collapseFortySeven" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortySeven">
        <div class="panel-body">
          The Procurement Integrated Enterprise Environment (PIEE) is the primary enterprise procure-to-pay (P2P) application for the Department of Defense and its supporting agencies and is trusted by
          companies reporting over $7.1 billion in spending.
          <br>References:
          <a href="https://piee.eb.mil/piee-landing/" target="_blank">
              About PIEE</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyEighth">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyEighth" aria-expanded="false" aria-controls="collapseFortyEighth">
            Programmable Logic Controller (PLC)
          </a>
        </h4>
      </div>
      <div id="collapseFortyEighth" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyEighth">
        <div class="panel-body">
          A solid-state control system that has a user-programmable memory for storing instructions for the purpose of implementing specific functions such as I/O control, logic, timing, counting, three mode
          (PID) control, communication, arithmetic, and data and file processing.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://csrc.nist.gov/glossary/term/PLC" target="_blank">
              About PLC</a>

        </div>
      </div>
    </div>


    `
  }
  if (letter_index == 'R'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFortyNine">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFortyNine" aria-expanded="false" aria-controls="collapseFortyNine">
            Radio Frequency (RF)
          </a>
        </h4>
      </div>
      <div id="collapseFortyNine" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFortyNine">
        <div class="panel-body">
          Wireless networking is an RF (radio frequency) technology. Air is the vehicle through which the data is carried, just as Ethernet uses copper cables. WLAN frequency ranges are in the 2.4GHz and 5GHZ
          bands. The most common legacy wireless standards, 802.11b and 802.11g, use the 2.4GHz range. IEEE 802.11a uses 5GHz exclusively. The newer 802.11n operates mostly in 5GHz but can also use the 2.4GHz
          band. The forthcoming 802.11ac standard operates in 5GHz. <br>
          Mobile, wireless, and IoT devices all operate within the radio frequency (RF) spectrum and allow hackers to easily compromise these devices. Due to the lack of visibility of wireless communications,
          devices roam freely and are undetected in corporate airspaces, enabling cyber-criminals to access intellectual property and sensitive company data. <br>
          These wireless blind spots—vulnerability to RF attacks on corporate networks—pose significant threats to enterprises.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
            CMMC Assessment Guide</a> and
          <a href="https://www.networkcomputing.com/networking/wireless-beginners-part-1-rf-and-waves" target="_blank">
              Wireless for beginners</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFifty">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFifty" aria-expanded="false" aria-controls="collapseFifty">
            Registered Practitioners (RP) and Registered Practitioners Organization (RPO)
          </a>
        </h4>
      </div>
      <div id="collapseFifty" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFifty">
        <div class="panel-body">
          The RPOs and RPs in the CMMC ecosystem provide advice, consulting, and recommendations to their clients.  They are the “implementers” and consultants, but do not conduct Certified Assessments.
          Any references to “non-certified” services are only referring to the fact that an RPO is not authorized to conduct a certified assessment.
          <br>References:
          <a href="https://cmmcab.org/rpo/" target="_blank">
              CMMC RPO</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyOne">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyOne" aria-expanded="false" aria-controls="collapseFiftyOne">
            Resilience Management Model (RMM)

          </a>
        </h4>
      </div>
      <div id="collapseFiftyOne" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyOne">
        <div class="panel-body">
          CERT-RMM, a maturity model derived from the Capability Maturity Model Integration (CMMI) for operational resilience, is the foundation for a process improvement approach to security, business continuity, and aspects of IT operations management. It establishes an organization's resilience management system: a collection of essential capabilities that the organization performs to ensure that its important assets stay productive in supporting business processes and services, even in the event of disruption.
          <br>References:
          <a href="https://www.sei.cmu.edu/news-events/news/article.cfm?assetid=494083" target="_blank">
              CERT RMM</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyTwo">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyTwo" aria-expanded="false" aria-controls="collapseFiftyTwo">
            Risk Management Framework  (RMF)
          </a>
        </h4>
      </div>
      <div id="collapseFiftyTwo" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyTwo">
        <div class="panel-body">
        The Risk Management Framework provides a process that integrates security and risk management activities into the system development life cycle. The risk-based approach to security control selection and
        specification considers effectiveness, efficiency, and constraints due to applicable laws, directives, Executive Orders, policies, standards, or regulations.
          <br>References:
          <a href="https://csrc.nist.gov/projects/risk-management/about-rmf" target="_blank">
              NIST Overview</a>,
          <a href="https://csrc.nist.gov/CSRC/media/Publications/sp/800-37/rev-2/draft/documents/sp800-37r2-discussion-draft.pdf" target="_blank">
              NIST Discussion draft</a> and
          <a href="https://csrc.nist.gov/projects/risk-management/about-rmf" target="_blank">
              NIST About RMF</a>
        </div>
      </div>
    </div>

    `
  }
  if (letter_index == 'S'){
    document.getElementById("mainContent").innerHTML =
    `
    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyThree">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyThree" aria-expanded="false" aria-controls="collapseFiftyThree">
            Section-889
          </a>
        </h4>
      </div>
      <div id="collapseFiftyThree" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyThree">
        <div class="panel-body">
          DoD, GSA, and NASA issued an interim rule amending the Federal Acquisition Regulation (FAR) to implement section 889(a)(1)(B) of the John S. McCain National Defense Authorization Act (NDAA) for
          Fiscal Year (FY) 2019 (Pub. L. 115-232). Section 889(a)(1)(B) prohibits executive agencies from entering into, or extending or renewing, a contract with an entity that uses any equipment, system,
          or service that uses covered telecommunications equipment or services as a substantial or essential component of any system, or as critical technology as part of any system, on or after August 13,
          2020, unless an exception applies or a waiver is granted. <br>
          Link lists the companies including their subsidiaries and affiliates.
          <br>References:
          <a href="https://www.acquisition.gov/FAR-Case-2019-009/889_Part_B" target="_blank">
              Interim Rule</a>,
          <a href="https://cmmcinfo.org/2020/11/23/complying-with-ndaa-section-889/" target="_blank">
              Comply with Section 889</a> and
          <a href="https://pacs.oregonstate.edu/sites/fa.oregonstate.edu/files/pacs/resources/prohibited_agreements_with_huawei.pdf" target="_blank">
            Prohibited agreements  </a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyFour">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyFour" aria-expanded="false" aria-controls="collapseFiftyFour">
            Security Incident Event Management (SIEM)
          </a>
        </h4>
      </div>
      <div id="collapseFiftyFour" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyFour">
        <div class="panel-body">
        IT teams use SIEM technology to collect log data across a business' infrastructure; this data comes from applications, networks, security devices and other sources. IT teams can then use this data to
        detect, categorize and analyze security incidents. Finally, with security insights in hand, IT teams can alert business leaders about security issues, produce compliance reports and discover the best ways
        to safeguard a business against cyber threats.
          <br>References:
          <a href="https://cybersecurity.att.com/blogs/security-essentials/siem-what-is-it-and-why-does-your-business-need-it" target="_blank">
              What is SIEM?</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyFive">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyFive" aria-expanded="false" aria-controls="collapseFiftyFive">
            Security Technical Implementation Guide (STIG)

          </a>
        </h4>
      </div>
      <div id="collapseFiftyFive" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyFive">
        <div class="panel-body">
          The Security Technical Implementation Guide (or STIG) documents describe cybersecurity requirements for a wide range of computer operating systems, routers, network equipment, software products and
          other computing systems. They are written by DISA, the Defense Information System Agency, part of the U.S. Department of Defense. <br>
          STIG details are based on concepts in NIST Special Publication 800-53, which specifies security controls for all U.S. federal information systems other than national security systems. <br>

          The STIG DoD website provides version specific documents/guidance on how to secure computer systems.
          <br>References:
          <a href="https://cromwell-intl.com/open-source/stig-compliance.html" target="_blank">
              STIG Requirements</a> and
          <a href="https://public.cyber.mil/stigs/" target="_blank">
              STIG's</a>
        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftySix">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftySix" aria-expanded="false" aria-controls="collapseFiftySix">
            Service Organization Control (SOC)
          </a>
        </h4>
      </div>
      <div id="collapseFiftySix" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftySix">
        <div class="panel-body">
          Increasingly, businesses outsource basic functions such as data storage and access to applications to cloud service providers (CSPs) and other service organizations. In response, the American
          Institute of Certified Public Accountants (AICPA) has developed the Service Organization Controls (SOC) framework, a standard for controls that safeguard the confidentiality and privacy of information
          stored and processed in the cloud. <br>
          Service audits based on the SOC framework fall into two categories — SOC 1 and SOC 2 — that apply to in-scope Microsoft cloud services. <br>
          SOC reports provide reasonable assurance that controls are in place at service organizations. <br>

          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
              CMMC Assessment Guide</a> and
          <a href="https://docs.microsoft.com/en-us/compliance/regulatory/offering-soc#:~:text=In%20response%2C%20the%20American%20Institute%20of%20Certified%20Public,of%20information%20stored%20and%20processed%20in%20the%20cloud." target="_blank">
              Microsoft about SOC</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftySeven">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftySeven" aria-expanded="false" aria-controls="collapseFiftySeven">
            Software as a Service (SaaS)
          </a>
        </h4>
      </div>
      <div id="collapseFiftySeven" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftySeven">
        <div class="panel-body">
          The capability provided to the consumer is to use the provider’s applications running on a cloud infrastructure. The applications are accessible from various client devices through either a thin
          client interface, such as a web browser (e.g., web-based email), or a program interface. The consumer does not manage or control the underlying cloud infrastructure including network, servers,
          operating systems, storage, or even individual application capabilities, with the possible exception of limited user-specific application configuration settings.
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
        CMMC Assessment Guide</a> and
          <a href="https://csrc.nist.gov/glossary/term/Software_as_a_Service" target="_blank">
              NISC.gov</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyEighth">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyEighth" aria-expanded="false" aria-controls="collapseFiftyEighth">
            Special Publication (SP)
          </a>
        </h4>
      </div>
      <div id="collapseFiftyEighth" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyEighth">
        <div class="panel-body">
          Include proceedings of conferences sponsored by NIST, NIST annual reports, and other special publications appropriate to this grouping such as wall charts, pocket cards, and bibliographies.<br>
          Special Publication – a designation for NIST documents, sometimes supporting FIPS.<br>
          Or <br>
          Microsoft’s term for a collection of patches integrated into a single large update.<br>
          <br>References:
          <a href="https://www.acq.osd.mil/cmmc/draft.html" target="_blank">
              CMMC Assessment Guide</a> and
          <a href="https://csrc.nist.gov/glossary/term/SP" target="_blank">
              NISC.gov</a>

        </div>
      </div>
    </div>


    <div class="panel panel-default">
      <div class="panel-heading" role="tab" id="headingFiftyNine">
        <h4 class="panel-title">
          <a class="collapsed" role="button" data-toggle="collapse" data-parent="#mainContent" href="#collapseFiftyNine" aria-expanded="false" aria-controls="collapseFiftyNine">
            Standard Procurement System (SPS)
          </a>
        </h4>
      </div>
      <div id="collapseFiftyNine" class="panel-collapse collapse" role="tabpanel" aria-labelledby="headingFiftyNine">
        <div class="panel-body">
        The Standard Procurement System (SPS) Program is the cornerstone for the DoD's paperless acquisition initiative. Procurement Desktop-Defense (PD2) provides automated strategic, streamlined contract
        management support for the procurement professional within a complete workflow management solution. The SPS Help Desk provides support for the SPS suite of products.
          <br>References:
          <a href="https://sps.caci.com/products.cfm" target="_blank">
              SPS</a>

        </div>
      </div>
    </div>

    `
  }
}
