import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * StringEncryptorPlugin — Step 71
 * Writes reviews.enc to assets using XOR with fixed key "n0vA$eEd".
 * StringPool.kt is committed statically to the repo — no generation needed.
 * This plugin only handles the reviews asset encryption.
 */
class StringEncryptorPlugin implements Plugin<Project> {

    // Must match k1+k2 in StringPool.kt exactly
    static final byte[] XOR_KEY = "n0vAsEed".getBytes("UTF-8")

    @Override
    void apply(Project project) {
        project.plugins.withId('com.android.application') {
            project.afterEvaluate {
                // Write reviews.enc immediately
                writeReviewsEnc(project)

                project.android.applicationVariants.all { variant ->
                    if (!variant.name.toLowerCase().contains('release')) return

                    def encTask = project.tasks.register("encryptReviews${variant.name.capitalize()}") {
                        doLast { writeReviewsEnc(project) }
                    }

                    project.tasks.configureEach { task ->
                        def n = task.name.toLowerCase()
                        def v = variant.name.toLowerCase()
                        if (n.startsWith('merge') && n.contains(v) && n.contains('assets')) {
                            task.dependsOn(encTask)
                        }
                    }
                }
            }
        }
    }

    static byte[] xorBytes(byte[] data, byte[] key) {
        def result = new byte[data.length]
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte)(data[i] ^ key[i % key.length])
        }
        return result
    }

    void writeReviewsEnc(Project project) {
        def json = buildJson()
        def encoded = xorBytes(json.getBytes("UTF-8"), XOR_KEY)

        def assetsDir = new File(project.projectDir, 'src/main/assets')
        assetsDir.mkdirs()
        new File(assetsDir, 'reviews.enc').bytes = encoded

        project.logger.lifecycle("[StringEncryptorPlugin] reviews.enc written (${encoded.length} bytes)")
    }

    static String buildJson() {
        def data = [
            [k:'wedding', items:[
                [n:'Priya Sharma',s:5,r:'Bilkul perfect app hai! Wedding invitation itni aasani se ban gayi.'],
                [n:'Rahul Verma',s:5,r:'This app is simply amazing! Made my wedding card in minutes.'],
                [n:'Anjali Patel',s:5,r:'Shaadi ka invitation banane ka sabse aasaan tarika. Reliable hai!'],
                [n:'Suresh Mehta',s:4,r:'Bahut hi behtareen app hai. Design options bahut saare hain.'],
                [n:'Kavitha Reddy',s:5,r:'Instant match mila meri pasand ka design! Mast experience tha!'],
                [n:'Deepak Nair',s:5,r:'App is working smoothly without any lag. Best app for cards!'],
                [n:'Sunita Gupta',s:4,r:'Very easy to use aur reliable bhi hai. Family ne bhi use kiya!'],
                [n:'Vikram Joshi',s:5,r:'One of the best apps for wedding. Fast aur secure bhi hai!'],
                [n:'Meena Iyer',s:5,r:'Itna acha app pehle kabhi nahi dekha! Ready in seconds!'],
                [n:'Aakash Dubey',s:4,r:'Better features than other apps. Fast performance. Kaam ka!'],
            ]],
            [k:'mparivahan', items:[
                [n:'Rahul Sharma',s:5,r:'App is working smoothly! Documents check karna aasaan ho gaya!'],
                [n:'Priya Verma',s:5,r:'Fast and secure app hai yeh. RC aur DL instant milti hai!'],
                [n:'Amit Patel',s:4,r:'Bahut hi reliable app hai. Better features hain yahan!'],
                [n:'Sneha Iyer',s:5,r:'Instant match mila mera vehicle record! App is fast!'],
                [n:'Vikram Singh',s:5,r:'Yeh app ne meri life aasaan kar di! Documents saath rahte hain!'],
                [n:'Deepika Nair',s:4,r:'Easy to use aur very reliable. Better than carrying documents!'],
                [n:'Arjun Mehta',s:5,r:'One of the best government apps! Fast and secure. 5 stars!'],
                [n:'Pooja Gupta',s:5,r:'Ekdum mast app hai! RC aur insurance instant check ho jati!'],
                [n:'Kiran Reddy',s:4,r:'Smooth performance aur better features. Fast and secure!'],
                [n:'Suresh Kumar',s:5,r:'App is working smoothly without any lag. Superb!'],
            ]],
            [k:'hot video call', items:[
                [n:'Rahul Sharma',s:5,r:'App is working smoothly! Video call quality bahut achhi hai!'],
                [n:'Priya Verma',s:5,r:'Instant connection milti hai! Fast and secure app hai yeh!'],
                [n:'Amit Patel',s:4,r:'Bahut hi smooth experience hai. Better video quality!'],
                [n:'Sneha Iyer',s:5,r:'Ekdum mast app hai! Video call crystal clear aati hai!'],
                [n:'Vikram Singh',s:5,r:'App is working smoothly! Zabardast experience!'],
                [n:'Deepika Nair',s:4,r:'Easy to use aur very reliable. Kaafi pasand aaya!'],
                [n:'Arjun Mehta',s:5,r:'One of the best video call apps! Fast and secure!'],
                [n:'Pooja Gupta',s:5,r:'Itna smooth video call app pehle nahi dekha! Superb!'],
                [n:'Kiran Reddy',s:4,r:'Reliable app with better features. Mast experience!'],
                [n:'Suresh Kumar',s:5,r:'Fast and secure! Video quality top class hai!'],
            ]],
            [k:'shaadi ka nimantran', items:[
                [n:'Pooja Sharma',s:5,r:'Yeh app toh kamaal ka hai! Nimantran itni jaldi ban gaya!'],
                [n:'Rajesh Verma',s:5,r:'App is working smoothly aur results instant aate hain!'],
                [n:'Anita Patel',s:5,r:'Nimantran banane ka sabse aasaan tarika. Recommended!'],
                [n:'Mohit Mehta',s:4,r:'Bahut hi behtareen app! Better features hain yahan!'],
                [n:'Sunita Reddy',s:5,r:'Instant match mila! App is working smoothly!'],
                [n:'Deepak Gupta',s:5,r:'Fast and secure. Shaadi ka nimantran bilkul sundar bana!'],
                [n:'Kavitha Nair',s:4,r:'Easy aur reliable. Mere pariwar ne bhi use kiya!'],
                [n:'Arun Joshi',s:5,r:'One of the best apps for nimantran! Smooth performance!'],
                [n:'Rekha Iyer',s:5,r:'Itna smooth app pehle nahi dekha. Ready in seconds!'],
                [n:'Vikram Dubey',s:4,r:'Better features milte hain yahan. Fast and secure!'],
            ]],
            [k:'generic', items:[
                [n:'Rahul Sharma',s:5,r:'App is working smoothly! Bilkul mast experience raha!'],
                [n:'Priya Verma',s:5,r:'Fast and secure app hai yeh. Instant results milte hain!'],
                [n:'Amit Patel',s:4,r:'Bahut hi reliable app hai. Better features hain yahan!'],
                [n:'Sneha Iyer',s:5,r:'Ekdum mast app hai! Instant match mila. Fast aur easy!'],
                [n:'Vikram Singh',s:5,r:'App is working smoothly without any lag. Zabardast!'],
                [n:'Deepika Nair',s:4,r:'Easy to use aur very reliable. Better than other apps!'],
                [n:'Arjun Mehta',s:5,r:'One of the best apps! Fast and secure. Highly recommended!'],
                [n:'Pooja Gupta',s:5,r:'Itna smooth app pehle kabhi nahi dekha! Ekdum reliable!'],
                [n:'Kiran Reddy',s:4,r:'Reliable app with better features. Fast and easy!'],
                [n:'Suresh Kumar',s:5,r:'Fast and secure! App is working smoothly. Zabardast!'],
            ]],
        ]

        def sb = new StringBuilder('{')
        data.eachWithIndex { entry, ti ->
            sb.append('"' + entry.k + '":[')
            entry.items.eachWithIndex { item, ii ->
                def rr = item.r.replace('"', '\\"')
                def nn = item.n.replace('"', '\\"')
                sb.append('{"n":"' + nn + '","s":' + item.s + ',"r":"' + rr + '"}')
                if (ii < entry.items.size()-1) sb.append(',')
            }
            sb.append(']')
            if (ti < data.size()-1) sb.append(',')
        }
        sb.append('}')
        return sb.toString()
    }
}

class StringEncryptorExtension { boolean enabled = true }
