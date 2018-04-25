/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.DefaultRequest;
import com.amazonaws.SignableRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.internal.AWS4SignerRequestParams;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.auth.profile.ProfilesConfigFile;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.AvailabilityZone;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.iterable.S3Objects;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.util.BinaryUtils;
import com.amazonaws.util.StringUtils;
import uk.co.lucasweb.aws.v4.signer.HttpRequest;
import uk.co.lucasweb.aws.v4.signer.Signer;
import uk.co.lucasweb.aws.v4.signer.credentials.AwsCredentials;

import static javax.crypto.Cipher.SECRET_KEY;

/**
 * This class is a starting point for working with the AWS SDK for Java, and
 * shows how to make a few simple requests to Amazon EC2 and Amazon S3.
 *
 * Before you run this code, be sure to fill in your AWS security credentials
 * in the  .aws/credentials file under your home directory.
 *
 * If you don't have an Amazon Web Services account, you can get started for free:
 *   http://aws.amazon.com/free
 *
 * For lots more information on using the AWS SDK for Java, including information on
 * high-level APIs and advanced features, check out the AWS SDK for Java Developer Guide:
 *   http://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/welcome.html
 *
 * Stay up to date with new features in the AWS SDK for Java by following the
 * AWS Java Developer Blog:
 *   https://java.awsblog.com
 */
public class AwsSdkSample {

    /*
     * Important: Be sure to fill in your AWS access credentials in the
     *            .aws/credentials file under your home directory 
     *             before you run this sample.
     * http://aws.amazon.com/security-credentials
     */
    static AmazonEC2 ec2;
    static AmazonS3  s3;


    /**
     * The only information needed to create a client are security credentials -
     * your AWS Access Key ID and Secret Access Key. All other
     * configuration, such as the service endpoints have defaults provided.
     *
     * Additional client parameters, such as proxy configuration, can be specified
     * in an optional ClientConfiguration object when constructing a client.
     *
     * @see com.amazonaws.auth.BasicAWSCredentials
     * @see com.amazonaws.auth.PropertiesCredentials
     * @see com.amazonaws.ClientConfiguration
     */
    private static void init() throws Exception {
        /*
         * ProfileCredentialsProvider loads AWS security credentials from a
         * .aws/config file in your home directory.
         *
         * These same credentials are used when working with other AWS SDKs and the AWS CLI.
         *
         * You can find more information on the AWS profiles config file here:
         * http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html
         */
        File configFile = new File(System.getProperty("user.home"), ".aws/credentials");
        AWSCredentialsProvider credentialsProvider = new ProfileCredentialsProvider(
            new ProfilesConfigFile(configFile), "default");

        if (credentialsProvider.getCredentials() == null) {
            throw new RuntimeException("No AWS security credentials found:\n"
                    + "Make sure you've configured your credentials in: " + configFile.getAbsolutePath() + "\n"
                    + "For more information on configuring your credentials, see "
                    + "http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html");
        }

        ec2 = new AmazonEC2Client(credentialsProvider);
        s3  = new AmazonS3Client(credentialsProvider);
    }

    protected boolean shouldExcludeHeaderFromSigning(String header) {
        return listOfHeadersToIgnoreInLowerCase.contains(header.toLowerCase());
    }

    private static final List<String> listOfHeadersToIgnoreInLowerCase = Arrays.asList("connection", "x-amzn-trace-id");

    private String buildAuthorizationHeader(SignableRequest<?> request, byte[] signature, AWSCredentials credentials, AWS4SignerRequestParams signerParams) {
        String signingCredentials = credentials.getAWSAccessKeyId() + "/" + signerParams.getScope();
        String credential = "Credential=" + signingCredentials;
        String signerHeaders = "SignedHeaders=" + this.getSignedHeadersString(request);
        String signatureHeader = "Signature=" + BinaryUtils.toHex(signature);
        StringBuilder authHeaderBuilder = new StringBuilder();
        authHeaderBuilder.append("AWS4-HMAC-SHA256").append(" ").append(credential).append(", ").append(signerHeaders).append(", ").append(signatureHeader);
        return authHeaderBuilder.toString();
    }
    protected String getSignedHeadersString(SignableRequest<?> request) {
        List<String> sortedHeaders = new ArrayList(request.getHeaders().keySet());
        Collections.sort(sortedHeaders, String.CASE_INSENSITIVE_ORDER);
        StringBuilder buffer = new StringBuilder();
        Iterator var4 = sortedHeaders.iterator();

        while(var4.hasNext()) {
            String header = (String)var4.next();
            if (!this.shouldExcludeHeaderFromSigning(header)) {
                if (buffer.length() > 0) {
                    buffer.append(";");
                }

                buffer.append(StringUtils.lowerCase(header));
            }
        }

        return buffer.toString();
    }

    private static String AWS_KEY="xxxx";
    private static String AWS_PASSWORD="xxxxx";

    public static void main(String args[]) throws URISyntaxException {


/*
        try {
            String contentSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            HttpRequest request = new HttpRequest("GET", new URI("https://bb7qx3qfl0.execute-api.us-east-1.amazonaws.com/test/firstFunction"));
            String signature = Signer.builder()
                    .awsCredentials(new AwsCredentials(AWS_KEY, AWS_PASSWORD))
                    .header("x-amz-date", "20130524T000000Z")
                    .header("x-amz-content-sha256", contentSha256)
                    .buildS3(request, contentSha256)
                    .getSignature();
            System.out.println("Siganutre es "+ signature);

        }
        catch(URISyntaxException ex)
        {
            ex.printStackTrace();
        }
*/


        BasicAWSCredentials basicCrendetials=new BasicAWSCredentials(AWS_KEY,AWS_PASSWORD);

        DefaultRequest t=new DefaultRequest("execute-api");
        t.setResourcePath("/test/firstFunction");
       t.setHttpMethod(HttpMethodName.GET);
        t.setEndpoint(new URI("https://bb7qx3qfl0.execute-api.us-east-1.amazonaws.com"));

        AWS4Signer signer=new AWS4Signer();

        signer.setServiceName(t.getServiceName());
        signer.sign(t,basicCrendetials);

        System.out.println(t.getHeaders());

    }

    public static void mainTo(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("Welcome to the AWS Java SDK!");
        System.out.println("===========================================");





        init();

        try {
            /*
             * The Amazon EC2 client allows you to easily launch and configure
             * computing capacity in AWS datacenters.
             *
             * In this sample, we use the EC2 client to list the availability zones
             * in a region, and then list the instances running in those zones.
             */
            DescribeAvailabilityZonesResult availabilityZonesResult = ec2.describeAvailabilityZones();
            List<AvailabilityZone> availabilityZones = availabilityZonesResult.getAvailabilityZones();
            System.out.println("You have access to " + availabilityZones.size() + " availability zones:");
            for (AvailabilityZone zone : availabilityZones) {
                System.out.println(" - " + zone.getZoneName() + " (" + zone.getRegionName() + ")");
            }

            DescribeInstancesResult describeInstancesResult = ec2.describeInstances();
            Set<Instance> instances = new HashSet<Instance>();
            for (Reservation reservation : describeInstancesResult.getReservations()) {
                instances.addAll(reservation.getInstances());
            }

            System.out.println("You have " + instances.size() + " Amazon EC2 instance(s) running.");


            /*
             * The Amazon S3 client allows you to manage and configure buckets
             * and to upload and download data.
             *
             * In this sample, we use the S3 client to list all the buckets in
             * your account, and then iterate over the object metadata for all
             * objects in one bucket to calculate the total object count and
             * space usage for that one bucket. Note that this sample only
             * retrieves the object's metadata and doesn't actually download the
             * object's content.
             *
             * In addition to the low-level Amazon S3 client in the SDK, there
             * is also a high-level TransferManager API that provides
             * asynchronous management of uploads and downloads with an easy to
             * use API:
             *   http://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/s3/transfer/TransferManager.html
             */
            List<Bucket> buckets = s3.listBuckets();
            System.out.println("You have " + buckets.size() + " Amazon S3 bucket(s).");

            if (buckets.size() > 0) {
                Bucket bucket = buckets.get(0);

                long totalSize  = 0;
                long totalItems = 0;
                /*
                 * The S3Objects and S3Versions classes provide convenient APIs
                 * for iterating over the contents of your buckets, without
                 * having to manually deal with response pagination.
                 */
                for (S3ObjectSummary objectSummary : S3Objects.inBucket(s3, bucket.getName())) {
                    totalSize += objectSummary.getSize();
                    totalItems++;
                }

                System.out.println("The bucket '" + bucket.getName() + "' contains "+ totalItems + " objects "
                        + "with a total size of " + totalSize + " bytes.");
            }
        } catch (AmazonServiceException ase) {
            /*
             * AmazonServiceExceptions represent an error response from an AWS
             * services, i.e. your request made it to AWS, but the AWS service
             * either found it invalid or encountered an error trying to execute
             * it.
             */
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            /*
             * AmazonClientExceptions represent an error that occurred inside
             * the client on the local host, either while trying to send the
             * request to AWS or interpret the response. For example, if no
             * network connection is available, the client won't be able to
             * connect to AWS to execute a request and will throw an
             * AmazonClientException.
             */
            System.out.println("Error Message: " + ace.getMessage());
        }
    }
}
